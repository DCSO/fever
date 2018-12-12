package processing

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

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
	DefaultHandler     Handler
	PerfStats          HandlerDispatcherPerfStats
	Logger             *log.Entry
	StatsEncoder       *util.PerformanceStatsEncoder
	StopCounterChan    chan bool
	StoppedCounterChan chan bool
}

// DefaultHandler is a built-in default handler which simply passes events on
// unchanged.
type DefaultHandler struct {
	DefaultOut chan types.Entry
}

// GetName just returns the name of the default handler
func (h *DefaultHandler) GetName() string {
	return "Default handler"
}

// GetEventTypes here is a dummy method -- since this handler is never
// registered we don't need to set this to an actual event type
func (h *DefaultHandler) GetEventTypes() []string {
	return []string{"not applicable"}
}

// Consume simply emits ths consumed entry on the default output channel
func (h *DefaultHandler) Consume(e *types.Entry) error {
	h.DefaultOut <- *e
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
			ad.Lock.Lock()
			ad.PerfStats.DispatchedPerSec /= uint64(ad.StatsEncoder.SubmitPeriod.Seconds())
			ad.StatsEncoder.Submit(ad.PerfStats)
			ad.PerfStats.DispatchedPerSec = 0
			sTime = time.Now()
			ad.Lock.Unlock()
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
		DefaultHandler: &DefaultHandler{
			DefaultOut: databaseOut,
		},
		Logger: log.WithFields(log.Fields{
			"domain": "dispatch",
		}),
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
	// by default just send entry to database
	if _, ok := ad.DispatchMap[e.EventType]; !ok {
		ad.DefaultHandler.Consume(e)
	}
	for _, agg := range ad.DispatchMap[e.EventType] {
		agg.Consume(e)
	}
	if a, ok := ad.DispatchMap["*"]; ok {
		for _, agg := range a {
			agg.Consume(e)
		}
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
