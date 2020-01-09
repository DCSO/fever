package processing

// DCSO FEVER
// Copyright (c) 2019, DCSO GmbH

import (
	"sync"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

// DebugOutputInterval specifies the amount of cache operations before
// printing the current cache size, in verbose mode.
const DebugOutputInterval = 100000

// GlobalContextCollector is a shared ContextCollector to be used by FEVER.
var GlobalContextCollector *ContextCollector

// ContextShipper is a function that processes a slice of Entries that make up a
// context of an alert, e.g. all events that share a flow ID relevant for the
// alert.
type ContextShipper func(Context, *log.Entry) error

// ContextCollectorPerfStats contains performance stats written to InfluxDB
// for monitoring.
type ContextCollectorPerfStats struct {
	Flows     uint64 `influx:"context_flows"`
	Events    uint64 `influx:"context_events"`
	JSONBytes uint64 `influx:"context_json_bytes"`
}

// ContextCollector is a component that maintains a cache of metadata per
// flow ID, forwarding it to a specified sink if associated with an alert.
type ContextCollector struct {
	PerfStats          ContextCollectorPerfStats
	StatsEncoder       *util.PerformanceStatsEncoder
	StopChan           chan bool
	StoppedChan        chan bool
	StopCounterChan    chan bool
	StoppedCounterChan chan bool
	Running            bool
	StatsLock          sync.Mutex
	FlowListeners      []chan types.Entry

	Cache    *cache.Cache
	MarkLock sync.Mutex
	Marked   map[string]struct{}
	Logger   *log.Entry
	i        uint64
	Ship     ContextShipper
}

// Context is a collection of JSON events that belong to a given flow.
type Context []string

// MakeContextCollector creates a new ContextCollector.
func MakeContextCollector(shipper ContextShipper, defaultTTL time.Duration) *ContextCollector {
	c := &ContextCollector{
		Logger: log.WithFields(log.Fields{
			"domain": "context",
		}),
		Cache:         cache.New(defaultTTL, defaultTTL),
		Marked:        make(map[string]struct{}),
		i:             0,
		Ship:          shipper,
		FlowListeners: make([]chan types.Entry, 0),
	}
	c.Logger.Debugf("created cache with default TTL %v", defaultTTL)
	return c
}

// Mark queues metadata for a given flow for forwarding, identified by its
// flow ID.
func (c *ContextCollector) Mark(flowID string) {
	// when seeing an alert, just mark the flow ID as relevant
	c.MarkLock.Lock()
	c.Marked[flowID] = struct{}{}
	c.MarkLock.Unlock()
}

// Consume processes an Entry, adding the data within to the internal
// aggregated state
func (c *ContextCollector) Consume(e *types.Entry) error {
	var myC Context
	// Some events, e.g. stats, have no flow ID set
	if e.FlowID == "" {
		return nil
	}

	cval, exist := c.Cache.Get(e.FlowID)
	if exist {
		// the 'flow' event always comes last, so we can use it as an
		// indicator that the flow is complete and can be processed
		if e.EventType == types.EventTypeFlow {
			var isMarked bool
			c.MarkLock.Lock()
			if _, ok := c.Marked[e.FlowID]; ok {
				isMarked = true
			}
			c.MarkLock.Unlock()
			if isMarked {
				c.StatsLock.Lock()
				c.PerfStats.Flows++
				c.PerfStats.Events += uint64(len(cval.(Context)))
				for _, v := range cval.(Context) {
					c.PerfStats.JSONBytes += uint64(len(v))
				}
				c.StatsLock.Unlock()
				if c.Ship != nil {
					c.Ship(cval.(Context), c.Logger)
				}
				for _, fl := range c.FlowListeners {
					fl <- *e
				}
				delete(c.Marked, e.FlowID)
			}
			c.Cache.Delete(e.FlowID)
		} else {
			myC = cval.(Context)
			myC = append(myC, e.JSONLine)
			c.Cache.Set(e.FlowID, myC, cache.DefaultExpiration)
		}
	} else {
		if e.EventType != types.EventTypeFlow {
			myC = append(myC, e.JSONLine)
			c.Cache.Set(e.FlowID, myC, cache.DefaultExpiration)
		}
	}
	c.i++
	if c.i%DebugOutputInterval == 0 {
		count := c.Cache.ItemCount()
		c.Logger.WithFields(log.Fields{
			"n": count,
		}).Debugf("cache size after another %d events", DebugOutputInterval)
		c.i = 0
	}
	return nil
}

func (c *ContextCollector) runCounter() {
	sTime := time.Now()
	for {
		time.Sleep(500 * time.Millisecond)
		select {
		case <-c.StopCounterChan:
			close(c.StoppedCounterChan)
			return
		default:
			if c.StatsEncoder == nil || time.Since(sTime) < c.StatsEncoder.SubmitPeriod {
				continue
			}
			c.StatsEncoder.Submit(c.PerfStats)
			c.StatsLock.Lock()
			c.PerfStats.JSONBytes = 0
			c.PerfStats.Flows = 0
			c.PerfStats.Events = 0
			sTime = time.Now()
			c.StatsLock.Unlock()
		}
	}
}

// GetName returns the name of the handler
func (c *ContextCollector) GetName() string {
	return "Context collector"
}

// GetEventTypes returns a slice of event type strings that this handler
// should be applied to
func (c *ContextCollector) GetEventTypes() []string {
	return []string{"*"}
}

// Run starts the metrics collection and submission in the ContextCollector.
func (c *ContextCollector) Run() {
	if !c.Running {
		c.StopChan = make(chan bool)
		c.StopCounterChan = make(chan bool)
		c.StoppedCounterChan = make(chan bool)
		go c.runCounter()
		c.Running = true
	}
}

// Stop stops the metrics collection and submission in the ContextCollector.
func (c *ContextCollector) Stop(stoppedChan chan bool) {
	if c.Running {
		close(c.StopCounterChan)
		<-c.StoppedCounterChan
		c.StoppedChan = stoppedChan
		close(c.StopChan)
		c.Running = false
	}
}

// SubmitStats registers a PerformanceStatsEncoder for runtime stats submission.
func (c *ContextCollector) SubmitStats(sc *util.PerformanceStatsEncoder) {
	c.StatsEncoder = sc
}

// AddFlowListener registers flowChan as a channel to emit a 'flow' Entry on
// whenever a marked flow is forwarded
func (c *ContextCollector) AddFlowListener(flowChan chan types.Entry) {
	c.FlowListeners = append(c.FlowListeners, flowChan)
}
