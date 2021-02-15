package processing

// DCSO FEVER
// Copyright (c) 2017, 2018, DCSO GmbH

import (
	"sync"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	log "github.com/sirupsen/logrus"
)

// HandlerDispatcherPerfStats contains performance stats written to InfluxDB
// for monitoring.
type HandlerDispatcherPerfStats struct {
	DispatchedPerSec uint64 `influx:"dispatch_calls_per_sec"`
}

// HandlerDispatcher is a component to collect and properly apply a set of
// Handlers to a stream of Entry objects. Handlers can register the event types
// they are meant to act on and are called with relevant Entries to perform
// their job.
type HandlerDispatcher struct {
	Lock               sync.Mutex
	DispatchMap        map[string]([]Handler)
	DBHandler          Handler
	PerfStats          HandlerDispatcherPerfStats
	Logger             *log.Entry
	StatsEncoder       *util.PerformanceStatsEncoder
	StopCounterChan    chan bool
	StoppedCounterChan chan bool
}

// DBHandler writes consumed events to a database.
type DBHandler struct {
	OutChan chan types.Entry
}

// GetName just returns the name of the default handler
func (h *DBHandler) GetName() string {
	return "Default handler"
}

// GetEventTypes here is a dummy method -- since this handler is never
// registered we don't need to set this to an actual event type
func (h *DBHandler) GetEventTypes() []string {
	return []string{"not applicable"}
}

// Consume simply emits the consumed entry on the default output channel
func (h *DBHandler) Consume(e *types.Entry) error {
	h.OutChan <- *e
	return nil
}

func (ad *HandlerDispatcher) runCounter() {
	sTime := time.Now()
	for {
		time.Sleep(500 * time.Millisecond)
		select {
		case <-ad.StopCounterChan:
			close(ad.StoppedCounterChan)
			return
		default:
			if ad.StatsEncoder == nil || time.Since(sTime) < ad.StatsEncoder.SubmitPeriod {
				continue
			}
			// Lock the current measurements for submission. Since this is a blocking
			// operation, we don't want this to depend on how long submitter.Submit()
			// takes but keep it independent of that. Hence we take the time to create
			// a local copy of the counter to be able to reset and release the live
			// one as quickly as possible.
			ad.Lock.Lock()
			// Make our own copy of the current counter
			myStats := HandlerDispatcherPerfStats{
				DispatchedPerSec: ad.PerfStats.DispatchedPerSec,
			}
			myStats.DispatchedPerSec /= uint64(ad.StatsEncoder.SubmitPeriod.Seconds())
			// Reset live counter
			ad.PerfStats.DispatchedPerSec = 0
			// Release live counter to not block further events
			ad.Lock.Unlock()

			ad.StatsEncoder.Submit(myStats)
			sTime = time.Now()
		}
	}
}

// MakeHandlerDispatcher returns a new HandlerDispatcher. The channel passed
// as an argument is used as an output channel for the default handler, which
// simply forwards events to a given channel (for example to be written to a
// database)
func MakeHandlerDispatcher(databaseOut chan types.Entry) *HandlerDispatcher {
	ad := &HandlerDispatcher{
		DispatchMap: make(map[string]([]Handler)),
		Logger: log.WithFields(log.Fields{
			"domain": "dispatch",
		}),
	}
	if databaseOut != nil {
		ad.DBHandler = &DBHandler{
			OutChan: databaseOut,
		}
	}
	ad.Logger.WithFields(log.Fields{
		"type": "*",
		"name": "default handler",
	}).Debugf("event handler added")
	return ad
}

// RegisterHandler adds the given Handler to the set of callbacks to be
// called on the relevant Entries received by the dispatcher.
func (ad *HandlerDispatcher) RegisterHandler(agg Handler) {
	eventTypes := agg.GetEventTypes()
	for _, eventType := range eventTypes {
		if _, ok := ad.DispatchMap[eventType]; !ok {
			ad.DispatchMap[eventType] = make([]Handler, 0)
		}
		ad.DispatchMap[eventType] = append(ad.DispatchMap[eventType], agg)
		ad.Logger.WithFields(log.Fields{
			"type": eventType,
			"name": agg.GetName(),
		}).Info("event handler added")
	}
}

// Dispatch applies the set of handlers currently registered in the dispatcher
// to the Entry object passed to it.
func (ad *HandlerDispatcher) Dispatch(e *types.Entry) {
	if _, ok := ad.DispatchMap[e.EventType]; ok {
		for _, agg := range ad.DispatchMap[e.EventType] {
			agg.Consume(e)
		}
	}
	if a, ok := ad.DispatchMap["*"]; ok {
		for _, agg := range a {
			agg.Consume(e)
		}
	}
	if ad.DBHandler != nil {
		ad.DBHandler.Consume(e)
	}
	ad.Lock.Lock()
	ad.PerfStats.DispatchedPerSec++
	ad.Lock.Unlock()
}

// SubmitStats registers a PerformanceStatsEncoder for runtime stats submission.
func (ad *HandlerDispatcher) SubmitStats(sc *util.PerformanceStatsEncoder) {
	ad.StatsEncoder = sc
}

// Run starts the background service for this handler
func (ad *HandlerDispatcher) Run() {
	ad.StopCounterChan = make(chan bool)
	ad.StoppedCounterChan = make(chan bool)
	go ad.runCounter()
}

// Stop causes the handler to cease counting and submitting data
func (ad *HandlerDispatcher) Stop(stopChan chan bool) {
	close(ad.StopCounterChan)
	<-ad.StoppedCounterChan
	close(stopChan)
}
