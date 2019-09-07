package processing

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	log "github.com/sirupsen/logrus"
)

// ForwardHandlerPerfStats contains performance stats written to InfluxDB
// for monitoring.
type ForwardHandlerPerfStats struct {
	ForwardedPerSec uint64 `influx:"forwarded_events_per_sec"`
}

// ForwardHandler is a handler that processes events by writing their JSON
// representation into a UNIX socket. This is limited by a list of allowed
// event types to be forwarded.
type ForwardHandler struct {
	Logger              *log.Entry
	DoRDNS              bool
	RDNSHandler         *RDNSHandler
	ContextCollector    *ContextCollector
	ForwardEventChan    chan []byte
	OutputSocket        string
	OutputConn          net.Conn
	Reconnecting        bool
	ReconnLock          sync.Mutex
	ReconnectNotifyChan chan bool
	StopReconnectChan   chan bool
	ReconnectTimes      int
	PerfStats           ForwardHandlerPerfStats
	StatsEncoder        *util.PerformanceStatsEncoder
	StopChan            chan bool
	StoppedChan         chan bool
	StopCounterChan     chan bool
	StoppedCounterChan  chan bool
	Running             bool
	Lock                sync.Mutex
}

func (fh *ForwardHandler) reconnectForward() {
	for range fh.ReconnectNotifyChan {
		var i int
		log.Info("Reconnecting to forwarding socket...")
		outputConn, myerror := net.Dial("unix", fh.OutputSocket)
		fh.ReconnLock.Lock()
		if !fh.Reconnecting {
			fh.Reconnecting = true
		} else {
			fh.ReconnLock.Unlock()
			continue
		}
		fh.ReconnLock.Unlock()
		for i = 0; (fh.ReconnectTimes == 0 || i < fh.ReconnectTimes) && myerror != nil; i++ {
			select {
			case <-fh.StopReconnectChan:
				return
			default:
				log.WithFields(log.Fields{
					"domain":     "forward",
					"retry":      i + 1,
					"maxretries": fh.ReconnectTimes,
				}).Warnf("error connecting to output socket, retrying: %s", myerror)
				time.Sleep(10 * time.Second)
				outputConn, myerror = net.Dial("unix", fh.OutputSocket)
			}
		}
		if myerror != nil {
			log.WithFields(log.Fields{
				"domain":  "forward",
				"retries": i,
			}).Fatalf("permanent error connecting to output socket: %s", myerror)
		} else {
			if i > 0 {
				log.WithFields(log.Fields{
					"domain":         "forward",
					"retry_attempts": i,
				}).Infof("connection to output socket successful")
			}
			fh.Lock.Lock()
			fh.OutputConn = outputConn
			fh.Lock.Unlock()
			fh.ReconnLock.Lock()
			fh.Reconnecting = false
			fh.ReconnLock.Unlock()
		}
	}
}

func (fh *ForwardHandler) runForward() {
	var err error
	for {
		select {
		case <-fh.StopChan:
			close(fh.StoppedChan)
			return
		default:
			for item := range fh.ForwardEventChan {
				select {
				case <-fh.StopChan:
					close(fh.StoppedChan)
					return
				default:
					fh.ReconnLock.Lock()
					if fh.Reconnecting {
						fh.ReconnLock.Unlock()
						continue
					}
					fh.ReconnLock.Unlock()
					fh.Lock.Lock()
					if fh.OutputConn != nil {
						_, err = fh.OutputConn.Write(item)
						if err != nil {
							fh.OutputConn.Close()
							log.Warn(err)
							fh.ReconnectNotifyChan <- true
							fh.Lock.Unlock()
							continue
						}
						_, err = fh.OutputConn.Write([]byte("\n"))
						if err != nil {
							fh.OutputConn.Close()
							log.Warn(err)
							fh.Lock.Unlock()
							continue
						}
					}
					fh.Lock.Unlock()
				}
			}
		}
	}
}

func (fh *ForwardHandler) runCounter() {
	sTime := time.Now()
	for {
		time.Sleep(500 * time.Millisecond)
		select {
		case <-fh.StopCounterChan:
			close(fh.StoppedCounterChan)
			return
		default:
			if fh.StatsEncoder == nil || time.Since(sTime) < fh.StatsEncoder.SubmitPeriod {
				continue
			}
			fh.Lock.Lock()
			fh.PerfStats.ForwardedPerSec /= uint64(fh.StatsEncoder.SubmitPeriod.Seconds())
			fh.StatsEncoder.Submit(fh.PerfStats)
			fh.PerfStats.ForwardedPerSec = 0
			sTime = time.Now()
			fh.Lock.Unlock()
		}
	}
}

// MakeForwardHandler creates a new forwarding handler
func MakeForwardHandler(reconnectTimes int, outputSocket string) *ForwardHandler {
	fh := &ForwardHandler{
		Logger: log.WithFields(log.Fields{
			"domain": "forward",
		}),
		OutputSocket:        outputSocket,
		ReconnectTimes:      reconnectTimes,
		ReconnectNotifyChan: make(chan bool),
		StopReconnectChan:   make(chan bool),
	}
	return fh
}

// Consume processes an Entry and forwards it
func (fh *ForwardHandler) Consume(e *types.Entry) error {
	doForwardThis := util.ForwardAllEvents || util.AllowType(e.EventType)
	if doForwardThis {
		var ev types.EveEvent
		err := json.Unmarshal([]byte(e.JSONLine), &ev)
		if err != nil {
			return err
		}
		if GlobalContextCollector != nil && e.EventType == types.EventTypeAlert {
			GlobalContextCollector.Mark(string(e.FlowID))
		}
		if fh.DoRDNS && fh.RDNSHandler != nil {
			err = fh.RDNSHandler.Consume(e)
			if err != nil {
				return err
			}
			ev.SrcHost = e.SrcHosts
			ev.DestHost = e.DestHosts
		}
		var jsonCopy []byte
		jsonCopy, err = json.Marshal(ev)
		if err != nil {
			return err
		}
		fh.ForwardEventChan <- jsonCopy
		fh.Lock.Lock()
		fh.PerfStats.ForwardedPerSec++
		fh.Lock.Unlock()
	}
	return nil
}

// GetName returns the name of the handler
func (fh *ForwardHandler) GetName() string {
	return "Forwarding handler"
}

// GetEventTypes returns a slice of event type strings that this handler
// should be applied to
func (fh *ForwardHandler) GetEventTypes() []string {
	if util.ForwardAllEvents {
		return []string{"*"}
	}
	return util.GetAllowedTypes()
}

// EnableRDNS switches on reverse DNS enrichment for source and destination
// IPs in outgoing EVE events.
func (fh *ForwardHandler) EnableRDNS(expiryPeriod time.Duration) {
	fh.DoRDNS = true
	fh.RDNSHandler = MakeRDNSHandler(util.NewHostNamer(expiryPeriod, 2*expiryPeriod))
}

// Run starts forwarding of JSON representations of all consumed events
func (fh *ForwardHandler) Run() {
	if !fh.Running {
		fh.StopChan = make(chan bool)
		fh.ForwardEventChan = make(chan []byte, 10000)
		fh.StopCounterChan = make(chan bool)
		fh.StoppedCounterChan = make(chan bool)
		go fh.reconnectForward()
		fh.ReconnectNotifyChan <- true
		go fh.runForward()
		go fh.runCounter()
		fh.Running = true
	}
}

// Stop stops forwarding of JSON representations of all consumed events
func (fh *ForwardHandler) Stop(stoppedChan chan bool) {
	if fh.Running {
		close(fh.StopCounterChan)
		<-fh.StoppedCounterChan
		fh.StoppedChan = stoppedChan
		fh.Lock.Lock()
		fh.OutputConn.Close()
		fh.Lock.Unlock()
		close(fh.StopReconnectChan)
		close(fh.StopChan)
		close(fh.ForwardEventChan)
		fh.Running = false
	}
}

// SubmitStats registers a PerformanceStatsEncoder for runtime stats submission.
func (fh *ForwardHandler) SubmitStats(sc *util.PerformanceStatsEncoder) {
	fh.StatsEncoder = sc
}
