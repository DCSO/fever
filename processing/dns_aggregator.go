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

// DNSAggregatorPerfStats contains performance stats written to InfluxDB
// for monitoring.
type DNSAggregatorPerfStats struct {
	DNSAggregateRawCount uint64 `influx:"dns_aggregate_raw_count"`
	DNSAggregateCount    uint64 `influx:"dns_aggregate_count"`
}

// AggregateDNSReplyDetails holds data for a query tuple.
type AggregateDNSReplyDetails struct {
	Rrtype string `json:"rrtype,omitempty"`
	Rdata  string `json:"rdata,omitempty"`
	Rcode  string `json:"rcode,omitempty"`
	Type   string `json:"type,omitempty"`
}

// AggregatedDNSDetails holds summarized traffic stats for a given
// AggregateDNSEvent.
type AggregatedDNSDetails struct {
	Rrname  string                     `json:"rrname,omitempty"`
	Details []AggregateDNSReplyDetails `json:"rdata,omitempty"`
}

// AggregateDNSEvent holds aggregated flow data.
type AggregateDNSEvent struct {
	Timestamp []string             `json:"timestamp"`
	EventType string               `json:"event_type"`
	SrcIP     []string             `json:"src_ip,omitempty"`
	SrcPort   []int                `json:"src_port,omitempty"`
	DestIP    []string             `json:"dest_ip,omitempty"`
	DestPort  int                  `json:"dest_port,omitempty"`
	DNS       AggregatedDNSDetails `json:"dns,omitempty"`
}

// DNSAggregator is an aggregator that groups DNS events with the same
// domain name.
type DNSAggregator struct {
	SensorID        string
	Count           int64
	DNSMutex        sync.RWMutex
	DNS             map[string]*AggregateDNSEvent
	PerfStats       DNSAggregatorPerfStats
	StatsEncoder    *util.PerformanceStatsEncoder
	SrcIPSet        map[string]bool
	DestIPSet       map[string]bool
	AnswerSet       map[string]bool
	StringBuf       bytes.Buffer
	FlushPeriod     time.Duration
	DatabaseOutChan chan types.Entry
	CloseChan       chan bool
	ClosedChan      chan bool
	Logger          *log.Entry
}

// MakeDNSAggregator creates a new empty DNSAggregator.
func MakeDNSAggregator(flushPeriod time.Duration, outChan chan types.Entry) *DNSAggregator {
	a := &DNSAggregator{
		FlushPeriod: flushPeriod,
		Logger: log.WithFields(log.Fields{
			"domain": "dns_aggregate",
		}),
		DNS:             make(map[string]*AggregateDNSEvent),
		SrcIPSet:        make(map[string]bool),
		DestIPSet:       make(map[string]bool),
		AnswerSet:       make(map[string]bool),
		DatabaseOutChan: outChan,
		CloseChan:       make(chan bool),
		ClosedChan:      make(chan bool),
	}
	a.SensorID, _ = os.Hostname()
	return a
}

func (a *DNSAggregator) flush() {
	// reset live counters
	a.DNSMutex.Lock()
	myDNS := a.DNS
	myCount := a.Count
	a.DNS = make(map[string]*AggregateDNSEvent)
	a.SrcIPSet = make(map[string]bool)
	a.DestIPSet = make(map[string]bool)
	a.AnswerSet = make(map[string]bool)
	a.Count = 0
	a.PerfStats.DNSAggregateCount = uint64(len(myDNS))
	a.PerfStats.DNSAggregateRawCount = uint64(myCount)
	a.DNSMutex.Unlock()
	if a.StatsEncoder != nil {
		a.StatsEncoder.Submit(a.PerfStats)
	}
	a.Logger.WithFields(log.Fields{
		"agg_dns": a.PerfStats.DNSAggregateCount,
		"in_dns":  a.PerfStats.DNSAggregateRawCount,
	}).Debug("flushing events")
	for _, v := range myDNS {
		jsonString, _ := json.Marshal(v)
		newEntry := types.Entry{
			Timestamp: v.Timestamp[0],
			EventType: v.EventType,
			JSONLine:  string(jsonString[:]),
		}
		a.DatabaseOutChan <- newEntry
	}
}

func (a *DNSAggregator) countRequest(key string, e *types.Entry) {
	a.DNSMutex.Lock()
	a.Count++
	if _, ok := a.DNS[key]; !ok {
		a.DNS[key] = &AggregateDNSEvent{
			Timestamp: []string{e.Timestamp},
			EventType: "dns",
			SrcIP:     []string{e.SrcIP},
			SrcPort:   []int{int(e.SrcPort)},
			DestIP:    []string{e.DestIP},
			DestPort:  int(e.DestPort),
			DNS: AggregatedDNSDetails{
				Rrname: e.DNSRRName,
				Details: []AggregateDNSReplyDetails{
					AggregateDNSReplyDetails{
						Rrtype: e.DNSRRType,
						Rdata:  e.DNSRData,
						Rcode:  e.DNSRCode,
						Type:   e.DNSType,
					},
				},
			},
		}
	} else {
		req := a.DNS[key]
		req.SrcPort = append(req.SrcPort, int(e.SrcPort))
		if _, ok := a.SrcIPSet[e.SrcIP]; !ok {
			req.SrcIP = append(req.SrcIP, e.SrcIP)
			a.SrcIPSet[e.SrcIP] = true
		}
		if _, ok := a.DestIPSet[e.DestIP]; !ok {
			req.DestIP = append(req.DestIP, e.DestIP)
			a.DestIPSet[e.DestIP] = true
		}
		a.StringBuf.Write([]byte(e.DNSRRType))
		a.StringBuf.Write([]byte(e.DNSRData))
		a.StringBuf.Write([]byte(e.DNSRCode))
		a.StringBuf.Write([]byte(e.DNSType))
		if _, ok = a.AnswerSet[a.StringBuf.String()]; !ok {
			req.DNS.Details = append(req.DNS.Details, AggregateDNSReplyDetails{
				Rrtype: e.DNSRRType,
				Rdata:  e.DNSRData,
				Rcode:  e.DNSRCode,
				Type:   e.DNSType,
			})
		}
		a.StringBuf.Reset()

	}
	a.DNSMutex.Unlock()
}

// Consume processes an Entry, adding the data within to the internal
// aggregated state
func (a *DNSAggregator) Consume(e *types.Entry) error {
	a.countRequest(e.DNSRRName, e)
	return nil
}

// Run starts the background aggregation service for this handler
func (a *DNSAggregator) Run() {
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

// Stop causes the aggregator to cease aggregating and submitting data
func (a *DNSAggregator) Stop(stopChan chan bool) {
	close(a.CloseChan)
	<-a.ClosedChan
	close(stopChan)
}

// SubmitStats registers a PerformanceStatsEncoder for runtime stats submission.
func (a *DNSAggregator) SubmitStats(sc *util.PerformanceStatsEncoder) {
	a.StatsEncoder = sc
}

// GetName returns the name of the handler
func (a *DNSAggregator) GetName() string {
	return "DB DNS aggregator"
}

// GetEventTypes returns a slice of event type strings that this handler
// should be applied to
func (a *DNSAggregator) GetEventTypes() []string {
	return []string{"dns"}
}
