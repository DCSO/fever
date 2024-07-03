package processing

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	TestFlowSrcIP        string
	TestFlowDestIP       string
	TestFlowDestPort     int64
	AllFlows             bool
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
	submitPeriod time.Duration, dummyMode bool, allFlows bool) *UnicornAggregator {
	a := &UnicornAggregator{
		Logger: log.WithFields(log.Fields{
			"domain": "aggregate",
		}),
		Submitter:        statsSubmitter,
		DummyMode:        dummyMode,
		SubmitPeriod:     submitPeriod,
		CloseChan:        make(chan bool),
		ClosedChan:       make(chan bool),
		Aggregate:        *MakeUnicornAggregate(),
		TestFlowDestPort: 99999,
		AllFlows:         allFlows,
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
	if a.TestFlowSrcIP != "" && a.TestFlowDestIP != "" {
		// Inject test flow into aggregation
		a.CountFlowTuple(
			fmt.Sprintf("%s_%s_%d", a.TestFlowSrcIP,
				a.TestFlowDestIP, a.TestFlowDestPort),
			23,
			42,
			20, // count 20 to ensure some limits are met downstream
		)
	}
	// Lock the current measurements for submission. Since this is a blocking
	// operation, we don't want this to depend on how long submitter.Submit()
	// takes but keep it independent of that. Hence we take the time to create
	// a local copy of the aggregate to be able to reset and release the live
	// one as quickly as possible.
	a.UnicornTuplesMutex.Lock()
	a.UnicornProxyMapMutex.Lock()
	// Make our own copy of the current aggregate, claiming ownership of the
	// maps with the measurements
	myAgg := UnicornAggregate{
		SensorID:       a.Aggregate.SensorID,
		TimestampStart: a.Aggregate.TimestampStart,
		TimestampEnd:   a.Aggregate.TimestampEnd,
		ProxyMap:       a.Aggregate.ProxyMap,
		FlowTuples:     a.Aggregate.FlowTuples,
	}
	// Replace live maps with empty ones
	a.Aggregate.FlowTuples = make(map[string](map[string]int64))
	a.Aggregate.ProxyMap = make(map[string](map[string]int64))
	// Release aggregate to not block further blocking ops on map contents
	a.UnicornTuplesMutex.Unlock()
	a.UnicornProxyMapMutex.Unlock()

	jsonString, myerror := json.Marshal(myAgg)
	if myerror == nil {
		a.Logger.WithFields(log.Fields{
			"flowtuples":   len(myAgg.FlowTuples),
			"http-destips": len(myAgg.ProxyMap)},
		).Info("preparing to submit")
		submitter.Submit(jsonString, "unicorn", "application/json")
	} else {
		a.Logger.Warn("error marshaling JSON for metadata aggregation")
	}

}

// CountFlowTuple increments the flow tuple counter for the given key. If addCnt
// is >1, then the caller is responsible for providing the correct (sub-total)
// counts for bytestoclient and bytestoserver.
func (a *UnicornAggregator) CountFlowTuple(key string, bytestoclient int64,
	bytestoserver int64, addCnt int64) {
	a.UnicornTuplesMutex.Lock()
	if _, ok := a.Aggregate.FlowTuples[key]; !ok {
		a.Aggregate.FlowTuples[key] = make(map[string]int64)
	}
	a.Aggregate.FlowTuples[key]["count"] += addCnt
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
				time.Sleep(100 * time.Millisecond)
				i += 100 * time.Millisecond
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
	if e.EventType == "flow" && (a.AllFlows || (e.Proto == "TCP" && e.BytesToClient > 0)) {
		a.StringBuf.Write([]byte(e.SrcIP))
		a.StringBuf.Write([]byte("_"))
		a.StringBuf.Write([]byte(e.DestIP))
		a.StringBuf.Write([]byte("_"))
		a.StringBuf.Write([]byte(strconv.Itoa(int(e.DestPort))))
		a.CountFlowTuple(a.StringBuf.String(), e.BytesToClient,
			e.BytesToServer, 1)
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

// EnableTestFlow adds a dummy flow with the given specs to each aggregation
func (a *UnicornAggregator) EnableTestFlow(srcip, dstip string, dstport int64) {
	a.TestFlowSrcIP = srcip
	a.TestFlowDestIP = dstip
	a.TestFlowDestPort = dstport
}
