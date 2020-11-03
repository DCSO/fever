package processing

// DCSO FEVER
// Copyright (c) 2020, DCSO GmbH

import (
	"fmt"
	"sync"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"
	log "github.com/sirupsen/logrus"
)

// ProtoProfile contains flow statistics for a give app layer protocol.
type ProtoProfile struct {
	PacketsToSrv uint64
	PacketsToClt uint64
	BytesToSrv   uint64
	BytesToClt   uint64
}

// FlowProfiler counts EVE event type statistics, such as number and size
// of JSON data received from the input.
type FlowProfiler struct {
	SensorID      string
	Host          string
	Profile       map[string]ProtoProfile
	FlushPeriod   time.Duration
	ProfileMutex  sync.Mutex
	CloseChan     chan bool
	ClosedChan    chan bool
	Logger        *log.Entry
	Submitter     util.StatsSubmitter
	SubmitChannel chan []byte
}

// MakeFlowProfiler creates a new FlowProfiler.
func MakeFlowProfiler(flushPeriod time.Duration, submitter util.StatsSubmitter) (*FlowProfiler, error) {
	a := &FlowProfiler{
		FlushPeriod: flushPeriod,
		Logger: log.WithFields(log.Fields{
			"domain": "flowprofiler",
		}),
		Profile:       make(map[string]ProtoProfile),
		CloseChan:     make(chan bool),
		ClosedChan:    make(chan bool),
		SubmitChannel: make(chan []byte, 60),
		Submitter:     submitter,
	}
	a.Host = getFQDN()
	return a, nil
}

func (a *FlowProfiler) formatLineProtocol() []string {
	out := make([]string, 0)
	a.ProfileMutex.Lock()
	myProfile := a.Profile
	for proto, protoVals := range myProfile {
		out = append(out, fmt.Sprintf("%s,host=%s,proto=%s flowbytestoclient=%d,flowbytestoserver=%d,flowpktstoclient=%d,flowpktstoserver=%d %d",
			util.ToolName, a.Host, proto,
			protoVals.BytesToClt, protoVals.BytesToSrv,
			protoVals.PacketsToClt, protoVals.PacketsToSrv,
			uint64(time.Now().UnixNano())))
		a.Profile[proto] = ProtoProfile{}
	}
	a.ProfileMutex.Unlock()
	return out
}

func (a *FlowProfiler) flush() {
	lineStrings := a.formatLineProtocol()
	for _, lineString := range lineStrings {
		select {
		case a.SubmitChannel <- []byte(lineString):
			break
		default:
			log.Warning("channel is full, cannot submit message...")
		}
	}
}

// Consume processes an Entry, adding the data within to the internal
// aggregated state
func (a *FlowProfiler) Consume(e *types.Entry) error {
	aproto := e.AppProto
	if aproto == "" {
		aproto = "unknown"
	}
	a.ProfileMutex.Lock()
	profile := a.Profile[aproto]
	profile.BytesToClt += uint64(e.BytesToClient)
	profile.BytesToSrv += uint64(e.BytesToServer)
	profile.PacketsToClt += uint64(e.PktsToClient)
	profile.PacketsToSrv += uint64(e.PktsToServer)
	a.Profile[aproto] = profile
	a.ProfileMutex.Unlock()
	return nil
}

// Run starts the background aggregation service for this handler
func (a *FlowProfiler) Run() {
	go func() {
		for message := range a.SubmitChannel {
			a.Submitter.SubmitWithHeaders(message, "", "text/plain", map[string]string{
				"database":         "telegraf",
				"retention_policy": "default",
			})
		}
	}()
	go func() {
		i := 0 * time.Second
		for {
			select {
			case <-a.CloseChan:
				close(a.SubmitChannel)
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
func (a *FlowProfiler) Stop(stopChan chan bool) {
	close(a.CloseChan)
	<-a.ClosedChan
	close(stopChan)
}

// GetName returns the name of the handler
func (a *FlowProfiler) GetName() string {
	return "Flow profiler"
}

// GetEventTypes returns a slice of event type strings that this handler
// should be applied to
func (a *FlowProfiler) GetEventTypes() []string {
	return []string{"flow"}
}
