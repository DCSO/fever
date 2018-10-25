package processing

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	"github.com/DCSO/bloom"
	log "github.com/sirupsen/logrus"
)

// FlowExtractor is an aggregator that extracts the flows from
// "hosts of interest" and sends them to the backend.
type FlowExtractor struct {
	SensorID      string
	BloomPath     string
	BloomFilter   *bloom.BloomFilter
	FlowsMutex    sync.RWMutex
	flowCount     int
	Flows         *bytes.Buffer
	SubmitChannel chan []byte
	Submitter     util.StatsSubmitter
	FlushPeriod   time.Duration
	FlushCount    int
	CloseChan     chan bool
	ClosedChan    chan bool
	Logger        *log.Entry
}

// MakeFlowExtractor creates a new empty FlowExtractor.
func MakeFlowExtractor(flushPeriod time.Duration, flushCount int, bloomPath string, submitter util.StatsSubmitter) (*FlowExtractor, error) {

	var bloomFilter *bloom.BloomFilter

	if bloomPath != "" {
		compressed := false
		if strings.HasSuffix(bloomPath, ".gz") {
			compressed = true
		}
		var err error
		bloomFilter, err = bloom.LoadFilter(bloomPath, compressed)
		if err != nil {
			return nil, err
		}
	}

	fe := &FlowExtractor{
		FlushPeriod: flushPeriod,
		Submitter:   submitter,
		BloomPath:   bloomPath,
		Logger: log.WithFields(log.Fields{
			"domain": "flow_extractor",
		}),
		Flows:         new(bytes.Buffer),
		SubmitChannel: make(chan []byte, 60),
		BloomFilter:   bloomFilter,
		CloseChan:     make(chan bool),
		ClosedChan:    make(chan bool),
		FlushCount:    flushCount,
		flowCount:     0,
	}
	fe.SensorID, _ = os.Hostname()
	return fe, nil
}

func (fe *FlowExtractor) flush() {
	fe.FlowsMutex.Lock()
	myFlows := fe.Flows
	fe.Flows = new(bytes.Buffer)
	fe.flowCount = 0
	fe.FlowsMutex.Unlock()
	select {
	case fe.SubmitChannel <- myFlows.Bytes():
		break
	default:
		log.Warning("Flow channel is full, cannot submit message...")
	}
}

// Consume processes an Entry, adding the data within to the flows
func (fe *FlowExtractor) Consume(e *types.Entry) error {
	fe.FlowsMutex.Lock()
	defer fe.FlowsMutex.Unlock()

	if fe.BloomFilter != nil {
		if !fe.BloomFilter.Check([]byte(e.SrcIP)) && !fe.BloomFilter.Check([]byte(e.DestIP)) {
			return nil
		}
	}

	var fev types.FlowEvent
	err := fev.FromEntry(e)

	if err != nil {
		return err
	}

	err = fev.Marshal(fe.Flows)

	fe.flowCount++

	return err
}

// Run starts the background aggregation service for this handler
func (fe *FlowExtractor) Run() {
	//this goroutine asynchronously submit flow messages
	go func() {
		for message := range fe.SubmitChannel {
			fe.Submitter.Submit(message, "", "application/binary-flows")
		}
	}()
	//this go routine takes care of flushing the flows
	go func() {
		i := 0 * time.Second
		interval := 100 * time.Millisecond
		for {
			select {
			case <-fe.CloseChan:
				close(fe.SubmitChannel)
				close(fe.ClosedChan)
				return
			default:
				//we flush if the flush period has passed, or if the count
				//of events is larger then the flush count
				fe.FlowsMutex.Lock()
				flowCount := fe.flowCount
				fe.FlowsMutex.Unlock()
				if i >= fe.FlushPeriod || flowCount > fe.FlushCount {
					fe.flush()
					i = 0 * time.Second
				}
				time.Sleep(interval)
				i += interval
			}
		}
	}()
}

// Stop causes the aggregator to cease aggregating and submitting data
func (fe *FlowExtractor) Stop(stopChan chan bool) {
	close(fe.CloseChan)
	<-fe.ClosedChan
	close(stopChan)
}

// GetName returns the name of the handler
func (fe *FlowExtractor) GetName() string {
	return "Flow extractor"
}

// GetEventTypes returns a slice of event type strings that this handler
// should be applied to
func (fe *FlowExtractor) GetEventTypes() []string {
	return []string{"flow"}
}
