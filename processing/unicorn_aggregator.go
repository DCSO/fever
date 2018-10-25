package processing

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	log "github.com/sirupsen/logrus"
)

// UnicornAggregate represents UNICORN relevant aggregated flow stats.
type UnicornAggregate struct {
	SensorID       string                        `json:"sensor-id"`
	TimestampStart time.Time                     `json:"time-start"`
	TimestampEnd   time.Time                     `json:"time-end"`
	FlowTuples     map[string](map[string]int64) `json:"tuples"`
	ProxyMap       map[string](map[string]int64) `json:"proxy-map"`
}

// UnicornAggregator collects and updates an internal structure of flow
// events grouped by route
type UnicornAggregator struct {
	Logger               *log.Entry
	Name                 string
	EventType            string
	Aggregate            UnicornAggregate
	Submitter            util.StatsSubmitter
	DummyMode            bool
	SubmitPeriod         time.Duration
	CloseChan            chan bool
	ClosedChan           chan bool
	StringBuf            bytes.Buffer
	UnicornTuplesMutex   sync.RWMutex `json:"-"`
	UnicornProxyMapMutex sync.RWMutex `json:"-"`
}

// MakeUnicornAggregate creates a new empty UnicornAggregate object.
func MakeUnicornAggregate() *UnicornAggregate {
	a := &UnicornAggregate{}
	a.SensorID, _ = os.Hostname()
	a.FlowTuples = make(map[string](map[string]int64))
	a.ProxyMap = make(map[string](map[string]int64))
	return a
}

// MakeUnicornAggregator creates a new empty UnicornAggregator object.
func MakeUnicornAggregator(statsSubmitter util.StatsSubmitter,
	submitPeriod time.Duration, dummyMode bool) *UnicornAggregator {
	a := &UnicornAggregator{
		Logger: log.WithFields(log.Fields{
			"domain": "aggregate",
		}),
		Submitter:    statsSubmitter,
		DummyMode:    dummyMode,
		SubmitPeriod: submitPeriod,
		CloseChan:    make(chan bool),
		ClosedChan:   make(chan bool),
		Aggregate:    *MakeUnicornAggregate(),
	}
	return a
}

func (a *UnicornAggregator) start() {
	timestamp := time.Now()
	a.Logger.WithFields(log.Fields{
		"timestamp": timestamp,
	}).Debug("aggregation started")
	a.Aggregate.TimestampStart = timestamp
}

func (a *UnicornAggregator) stop() {
	timestamp := time.Now()
	a.Logger.WithFields(log.Fields{
		"timestamp": timestamp,
	}).Debug("aggregation stopped")
	a.Aggregate.TimestampEnd = timestamp
}

func (a *UnicornAggregator) submit(submitter util.StatsSubmitter, dummyMode bool) {
	a.UnicornTuplesMutex.Lock()
	a.UnicornProxyMapMutex.Lock()
	jsonString, myerror := json.Marshal(a.Aggregate)
	if myerror == nil {
		a.Logger.WithFields(log.Fields{
			"flowtuples":   len(a.Aggregate.FlowTuples),
			"http-destips": len(a.Aggregate.ProxyMap)},
		).Info("preparing to submit")
		submitter.Submit(jsonString, "unicorn", "application/json")
	} else {
		a.Logger.Warn("error marshaling JSON for metadata aggregation")
	}
	a.Aggregate.FlowTuples = make(map[string](map[string]int64))
	a.Aggregate.ProxyMap = make(map[string](map[string]int64))
	a.UnicornTuplesMutex.Unlock()
	a.UnicornProxyMapMutex.Unlock()
}

// CountFlowTuple increments the flow tuple counter for the given key.
func (a *UnicornAggregator) CountFlowTuple(key string, bytestoclient int64,
	bytestoserver int64) {
	a.UnicornTuplesMutex.Lock()
	if _, ok := a.Aggregate.FlowTuples[key]; !ok {
		a.Aggregate.FlowTuples[key] = make(map[string]int64)
	}
	a.Aggregate.FlowTuples[key]["count"]++
	a.Aggregate.FlowTuples[key]["total_bytes_toclient"] += bytestoclient
	a.Aggregate.FlowTuples[key]["total_bytes_toserver"] += bytestoserver
	a.UnicornTuplesMutex.Unlock()
}

// CountHTTPHost increments the count for the given IP-hostname pair.
func (a *UnicornAggregator) CountHTTPHost(destip string, hostname string) {
	a.UnicornProxyMapMutex.Lock()
	if _, ok := a.Aggregate.ProxyMap[destip]; !ok {
		a.Aggregate.ProxyMap[destip] = make(map[string]int64)
	}
	a.Aggregate.ProxyMap[destip][hostname]++
	a.UnicornProxyMapMutex.Unlock()
}

// Run starts the background aggregation service for this handler
func (a *UnicornAggregator) Run() {
	go func() {
		i := 0 * time.Second
		a.start()
		for {
			select {
			case <-a.CloseChan:
				close(a.ClosedChan)
				return
			default:
				if i >= a.SubmitPeriod {
					a.stop()
					a.submit(a.Submitter, a.DummyMode)
					a.start()
					i = 0 * time.Second
				}
				time.Sleep(1 * time.Second)
				i += 1 * time.Second
			}
		}
	}()
}

// Stop causes the aggregator to cease aggregating and submitting data
func (a *UnicornAggregator) Stop(stopChan chan bool) {
	close(a.CloseChan)
	<-a.ClosedChan
	close(stopChan)
}

// Consume processes an Entry, adding the data within to the internal
// aggregated state
func (a *UnicornAggregator) Consume(e *types.Entry) error {
	// Unicorn flow aggregation update
	if e.EventType == "flow" && e.Proto == "TCP" && e.BytesToClient > 0 {
		a.StringBuf.Write([]byte(e.SrcIP))
		a.StringBuf.Write([]byte("_"))
		a.StringBuf.Write([]byte(e.DestIP))
		a.StringBuf.Write([]byte("_"))
		a.StringBuf.Write([]byte(strconv.Itoa(int(e.DestPort))))
		a.CountFlowTuple(a.StringBuf.String(), e.BytesToClient,
			e.BytesToServer)
		a.StringBuf.Reset()
	}

	// Proxy detection update
	if e.EventType == "http" {
		if (e.DestPort >= 8000 && e.DestPort <= 8999) || e.DestPort == 3128 || e.DestPort == 80 {
			a.CountHTTPHost(e.DestIP, e.HTTPHost)
		}
	}
	return nil
}

// GetName returns the name of the handler
func (a *UnicornAggregator) GetName() string {
	return "Unicorn aggregator/submitter"
}

// GetEventTypes returns a slice of event type strings that this handler
// should be applied to
func (a *UnicornAggregator) GetEventTypes() []string {
	return []string{"http", "flow"}
}
