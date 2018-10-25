package processing

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"bytes"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	log "github.com/sirupsen/logrus"
)

// FlowAggregatorPerfStats contains performance stats written to InfluxDB
// for monitoring.
type FlowAggregatorPerfStats struct {
	FlowAggregateRawCount uint64 `influx:"flow_aggregate_raw_count"`
	FlowAggregateCount    uint64 `influx:"flow_aggregate_count"`
}

// AggregatedFlowDetails holds summarized traffic stats for a given
// AggregateFlowEvent.
type AggregatedFlowDetails struct {
	PktsToserver  int64 `json:"pkts_toserver"`
	PktsToclient  int64 `json:"pkts_toclient"`
	BytesToserver int64 `json:"bytes_toserver"`
	BytesToclient int64 `json:"bytes_toclient"`
}

// AggregateFlowEvent holds aggregated flow data.
type AggregateFlowEvent struct {
	Timestamp []string              `json:"timestamp"`
	EventType string                `json:"event_type"`
	SrcIP     string                `json:"src_ip,omitempty"`
	SrcPort   []int                 `json:"src_port,omitempty"`
	DestIP    string                `json:"dest_ip,omitempty"`
	DestPort  int                   `json:"dest_port,omitempty"`
	Flow      AggregatedFlowDetails `json:"flow,omitempty"`
}

// FlowAggregator is an aggregator that groups flows with the same combination
// of srcIP/destIP/destPort.
type FlowAggregator struct {
	SensorID        string
	Count           int64
	FlowsMutex      sync.RWMutex
	Flows           map[string]*AggregateFlowEvent
	PerfStats       FlowAggregatorPerfStats
	StatsEncoder    *util.PerformanceStatsEncoder
	FlushPeriod     time.Duration
	StringBuf       bytes.Buffer
	DatabaseOutChan chan types.Entry
	CloseChan       chan bool
	ClosedChan      chan bool
	Logger          *log.Entry
}

// MakeFlowAggregator creates a new empty FlowAggregator.
func MakeFlowAggregator(flushPeriod time.Duration, outChan chan types.Entry) *FlowAggregator {
	a := &FlowAggregator{
		FlushPeriod: flushPeriod,
		Logger: log.WithFields(log.Fields{
			"domain": "flow_aggregate",
		}),
		Flows:           make(map[string]*AggregateFlowEvent),
		DatabaseOutChan: outChan,
		CloseChan:       make(chan bool),
		ClosedChan:      make(chan bool),
	}
	a.SensorID, _ = os.Hostname()
	return a
}

func (a *FlowAggregator) flush() {
	a.FlowsMutex.Lock()
	myFlows := a.Flows
	myCount := a.Count
	a.Flows = make(map[string]*AggregateFlowEvent)
	a.Count = 0
	a.PerfStats.FlowAggregateRawCount = uint64(myCount)
	a.PerfStats.FlowAggregateCount = uint64(len(myFlows))
	a.FlowsMutex.Unlock()
	if a.StatsEncoder != nil {
		a.StatsEncoder.Submit(a.PerfStats)
	}
	a.Logger.WithFields(log.Fields{
		"agg_flows": a.PerfStats.FlowAggregateCount,
		"in_flows":  a.PerfStats.FlowAggregateRawCount,
	}).Info("flushing events")
	for _, v := range myFlows {
		jsonString, _ := json.Marshal(v)
		newEntry := types.Entry{
			SrcIP:     v.SrcIP,
			SrcPort:   int64(v.SrcPort[0]),
			DestIP:    v.DestIP,
			DestPort:  int64(v.DestPort),
			Timestamp: v.Timestamp[0],
			EventType: v.EventType,
			JSONLine:  string(jsonString[:]),
		}
		a.DatabaseOutChan <- newEntry
	}
}

func (a *FlowAggregator) countFlow(key string, e *types.Entry) {
	a.FlowsMutex.Lock()
	a.Count++
	if _, ok := a.Flows[key]; !ok {
		a.Flows[key] = &AggregateFlowEvent{
			Timestamp: []string{e.Timestamp},
			EventType: "flow",
			SrcIP:     e.SrcIP,
			SrcPort:   []int{int(e.SrcPort)},
			DestIP:    e.DestIP,
			DestPort:  int(e.DestPort),
			Flow: AggregatedFlowDetails{
				PktsToserver:  e.PktsToServer,
				PktsToclient:  e.PktsToClient,
				BytesToserver: e.BytesToServer,
				BytesToclient: e.BytesToClient,
			},
		}
	} else {
		flow := a.Flows[key]
		flow.SrcPort = append(flow.SrcPort, int(e.SrcPort))
		flow.Flow.PktsToserver += e.PktsToServer
		flow.Flow.PktsToclient += e.PktsToClient
		flow.Flow.BytesToserver += e.BytesToServer
		flow.Flow.BytesToclient += e.BytesToClient
	}
	a.FlowsMutex.Unlock()
}

// Consume processes an Entry, adding the data within to the internal
// aggregated state
func (a *FlowAggregator) Consume(e *types.Entry) error {
	a.StringBuf.Write([]byte(e.SrcIP))
	a.StringBuf.Write([]byte(e.DestIP))
	a.StringBuf.Write([]byte(string(e.DestPort)))
	a.countFlow(a.StringBuf.String(), e)
	a.StringBuf.Reset()
	return nil
}

// Run starts the background aggregation service for this handler
func (a *FlowAggregator) Run() {
	go func() {
		i := 0 * time.Second
		for {
			select {
			case <-a.CloseChan:
				close(a.ClosedChan)
				return
			default:
				if i >= a.FlushPeriod {
					a.flush()
					i = 0 * time.Second
				}
				time.Sleep(1 * time.Second)
				i += 1 * time.Second
			}
		}
	}()
}

// SubmitStats registers a PerformanceStatsEncoder for runtime stats submission.
func (a *FlowAggregator) SubmitStats(sc *util.PerformanceStatsEncoder) {
	a.StatsEncoder = sc
}

// Stop causes the aggregator to cease aggregating and submitting data
func (a *FlowAggregator) Stop(stopChan chan bool) {
	close(a.CloseChan)
	<-a.ClosedChan
	close(stopChan)
}

// GetName returns the name of the handler
func (a *FlowAggregator) GetName() string {
	return "DB flow aggregator"
}

// GetEventTypes returns a slice of event type strings that this handler
// should be applied to
func (a *FlowAggregator) GetEventTypes() []string {
	return []string{"flow"}
}
