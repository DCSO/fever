package processing

// DCSO FEVER
// Copyright (c) 2018, DCSO GmbH

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"
	log "github.com/sirupsen/logrus"
)

// EventProfile contains counts per event_type such as occurrences and
// JSON size.
type EventProfile struct {
	CountMap map[string]uint64
	SizeMap  map[string]uint64
}

// EventProfiler counts EVE event type statistics, such as number and size
// of JSON data received from the input.
type EventProfiler struct {
	SensorID      string
	Host          string
	Profile       EventProfile
	FlushPeriod   time.Duration
	ProfileMutex  sync.Mutex
	CloseChan     chan bool
	ClosedChan    chan bool
	Logger        *log.Entry
	Submitter     util.StatsSubmitter
	SubmitChannel chan []byte
}

func getFQDN() (fqdn string) {
	cmd := exec.Command("/bin/hostname", "-f")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Warn(err)
		host, err := os.Hostname()
		if err != nil {
			return "unknown"
		}
		return host
	}
	fqdn = out.String()
	if len(fqdn) > 1 {
		fqdn = fqdn[:len(fqdn)-1]
	} else {
		fqdn = "unknown"
	}
	return fqdn
}

// MakeEventProfiler creates a new EventProfiler.
func MakeEventProfiler(flushPeriod time.Duration, submitter util.StatsSubmitter) (*EventProfiler, error) {
	sensorID, err := util.GetSensorID()
	if err != nil {
		return nil, err
	}
	a := &EventProfiler{
		FlushPeriod: flushPeriod,
		Logger: log.WithFields(log.Fields{
			"domain": "eventprofiler",
		}),
		Profile: EventProfile{
			CountMap: make(map[string]uint64),
			SizeMap:  make(map[string]uint64),
		},
		CloseChan:     make(chan bool),
		ClosedChan:    make(chan bool),
		SubmitChannel: make(chan []byte, 60),
		Submitter:     submitter,
		SensorID:      sensorID,
	}
	a.SensorID, _ = os.Hostname()
	a.Host = getFQDN()
	return a, nil
}

func (a *EventProfiler) formatLineProtocol() string {
	out := ""
	a.ProfileMutex.Lock()
	myProfile := a.Profile
	first := true
	for k, v := range myProfile.SizeMap {
		if !first {
			out += ","
		} else {
			first = false
		}
		out += fmt.Sprintf("size.%s=%d", k, v)
	}
	for k, v := range myProfile.CountMap {
		out += fmt.Sprintf(",count.%s=%d", k, v)
	}
	a.ProfileMutex.Unlock()
	if out == "" {
		return ""
	}
	return fmt.Sprintf("%s,host=%s %s %d", util.ToolName, a.Host, out, uint64(time.Now().UnixNano()))
}

func (a *EventProfiler) flush() {
	lineString := a.formatLineProtocol()
	if lineString == "" {
		return
	}
	select {
	case a.SubmitChannel <- []byte(lineString):
		break
	default:
		log.Warning("channel is full, cannot submit message...")
	}
}

// Consume processes an Entry, adding the data within to the internal
// aggregated state
func (a *EventProfiler) Consume(e *types.Entry) error {
	etype := e.EventType
	a.ProfileMutex.Lock()
	a.Profile.CountMap[etype]++
	a.Profile.SizeMap[etype] += uint64(len(e.JSONLine))
	a.ProfileMutex.Unlock()
	return nil
}

// Run starts the background aggregation service for this handler
func (a *EventProfiler) Run() {
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
func (a *EventProfiler) Stop(stopChan chan bool) {
	close(a.CloseChan)
	<-a.ClosedChan
	close(stopChan)
}

// GetName returns the name of the handler
func (a *EventProfiler) GetName() string {
	return "Event profiler"
}

// GetEventTypes returns a slice of event type strings that this handler
// should be applied to
func (a *EventProfiler) GetEventTypes() []string {
	return []string{"*"}
}
