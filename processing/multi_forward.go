package processing

// DCSO FEVER
// Copyright (c) 2021, DCSO GmbH

import (
	"net"
	"sync"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"
	log "github.com/sirupsen/logrus"
)

// MultiForwardPerfStats contains performance stats written to InfluxDB
// for monitoring.
type MultiForwardPerfStats struct {
	Received     uint64 `influx:"output_received_per_sec"`
	Dropped      uint64 `influx:"output_dropped"`
	BufferLength uint64 `influx:"output_buffer_length"`
}

// MultiForwardOutput defines a single output target including socket path,
// whether to filter the output by event type and if so, what event types to let
// pass.
type MultiForwardOutput struct {
	Socket string
	All    bool
	Types  []string
}

// MultiForwardConfiguration contains a setup for the multi-forwarder as read
// and parsed from the configuration file.
type MultiForwardConfiguration struct {
	Outputs      map[string]MultiForwardOutput `mapstructure:"multi-forward"`
	Shippers     []*MultiForwardShipper
	StatsEncoder *util.PerformanceStatsEncoder
}

// MultiForwardShipper is a concurrent, self-contained component that receives
// Entries from an input channel and writes the associated JSON to an output
// socket, filtering the output if desired. Also handles reconnection.
type MultiForwardShipper struct {
	OutputName          string
	Logger              *log.Entry
	ForwardInChan       chan types.Entry
	OutputSocket        string
	OutputConn          net.Conn
	Reconnecting        bool
	ReconnLock          sync.Mutex
	ReconnectNotifyChan chan bool
	StopReconnectChan   chan bool
	ReconnectTimes      int
	PerfStats           MultiForwardPerfStats
	StatsEncoder        *util.PerformanceStatsEncoder
	StopChan            chan bool
	StoppedChan         chan bool
	StopCounterChan     chan bool
	StoppedCounterChan  chan bool
	Running             bool
	Lock                sync.Mutex
}

func (mfs *MultiForwardShipper) reconnectForward() {
	for range mfs.ReconnectNotifyChan {
		var i int
		mfs.Logger.Infof("Reconnecting to forwarding socket (%s)...", mfs.OutputSocket)
		outputConn, myerror := net.Dial("unix", mfs.OutputSocket)
		mfs.ReconnLock.Lock()
		if !mfs.Reconnecting {
			mfs.Reconnecting = true
		} else {
			mfs.ReconnLock.Unlock()
			continue
		}
		mfs.ReconnLock.Unlock()

		for i = 0; (mfs.ReconnectTimes == 0 || i < mfs.ReconnectTimes) && myerror != nil; i++ {
			select {
			case <-mfs.StopReconnectChan:
				return
			default:
				mfs.Logger.WithFields(log.Fields{
					"retry":      i + 1,
					"maxretries": mfs.ReconnectTimes,
				}).Warnf("error connecting to output socket, retrying: %s", myerror)
				time.Sleep(10 * time.Second)
				outputConn, myerror = net.Dial("unix", mfs.OutputSocket)
			}
		}
		if myerror != nil {
			mfs.Logger.WithFields(log.Fields{
				"retries": i,
			}).Fatalf("permanent error connecting to output socket: %s", myerror)
			mfs.ReconnLock.Unlock()
		} else {
			if i > 0 {
				mfs.Logger.WithFields(log.Fields{
					"retry_attempts": i,
				}).Infof("connection to output socket successful")
			}
			mfs.Lock.Lock()
			mfs.OutputConn = outputConn
			mfs.Lock.Unlock()
			mfs.ReconnLock.Lock()
			mfs.Reconnecting = false
			mfs.ReconnLock.Unlock()
		}
	}
}

func (mfs *MultiForwardShipper) runForward() {
	var err error
	for {
		select {
		case <-mfs.StopChan:
			close(mfs.StoppedChan)
			return
		default:
			for item := range mfs.ForwardInChan {
				mfs.PerfStats.Received++
				select {
				case <-mfs.StopChan:
					close(mfs.StoppedChan)
					return
				default:
					mfs.ReconnLock.Lock()
					if mfs.Reconnecting {
						mfs.ReconnLock.Unlock()
						mfs.PerfStats.Dropped++
						continue
					}
					mfs.ReconnLock.Unlock()
					mfs.Lock.Lock()
					if mfs.OutputConn != nil {
						_, err = mfs.OutputConn.Write([]byte(item.JSONLine))
						if err != nil {
							mfs.OutputConn.Close()
							mfs.Lock.Unlock()
							log.Warn(err)
							mfs.ReconnectNotifyChan <- true
							continue
						}
						_, err = mfs.OutputConn.Write([]byte("\n"))
						if err != nil {
							mfs.OutputConn.Close()
							mfs.Lock.Unlock()
							mfs.Logger.Warn(err)
							continue
						}
					}
					mfs.Lock.Unlock()
				}
			}
		}
	}
}

func (mfs *MultiForwardShipper) runCounter() {
	sTime := time.Now()
	for {
		time.Sleep(500 * time.Millisecond)
		select {
		case <-mfs.StopCounterChan:
			close(mfs.StoppedCounterChan)
			return
		default:
			if mfs.StatsEncoder == nil || time.Since(sTime) < mfs.StatsEncoder.SubmitPeriod {
				continue
			}
			// Lock the current measurements for submission. Since this is a blocking
			// operation, we don't want this to depend on how long submitter.Submit()
			// takes but keep it independent of that. Hence we take the time to create
			// a local copy of the counter to be able to reset and release the live
			// one as quickly as possible.
			mfs.Lock.Lock()
			// Make our own copy of the current counter
			myStats := MultiForwardPerfStats{
				Dropped:      mfs.PerfStats.Dropped,
				Received:     mfs.PerfStats.Received / uint64(mfs.StatsEncoder.SubmitPeriod.Seconds()),
				BufferLength: uint64(len(mfs.ForwardInChan)),
			}
			// Reset live counter
			mfs.PerfStats.Received = 0
			// Release live counter to not block further events
			mfs.Lock.Unlock()

			mfs.StatsEncoder.SubmitWithTags(myStats, map[string]string{
				"output": mfs.OutputName,
			})
			sTime = time.Now()
		}
	}
}

// Run starts all concurrent aspects of the forwarder, reading from the input
// channel and distributing incoming events after setting up the shippers from
// the configuration.
func (m *MultiForwardConfiguration) Run(inChan <-chan types.Entry, reconnectTimes int) {
	outputMap := make(map[string][]*MultiForwardShipper)
	fwdAll := make([]*MultiForwardShipper, 0)
	for name, output := range m.Outputs {
		mfs := &MultiForwardShipper{
			OutputName:     name,
			OutputSocket:   output.Socket,
			ReconnectTimes: reconnectTimes,
			Logger: log.WithFields(log.Fields{
				"domain": "forward",
				"output": name,
			}),
			ReconnectNotifyChan: make(chan bool),
			StopReconnectChan:   make(chan bool),
			StatsEncoder:        m.StatsEncoder,
		}
		mfs.StopChan = make(chan bool)
		mfs.ForwardInChan = make(chan types.Entry, 10000)
		if output.All {
			fwdAll = append(fwdAll, mfs)
		} else {
			for _, outT := range output.Types {
				outputMap[outT] = append(outputMap[outT], mfs)
			}
		}
		mfs.StopCounterChan = make(chan bool)
		mfs.StoppedCounterChan = make(chan bool)
		go mfs.reconnectForward()
		mfs.ReconnectNotifyChan <- true
		go mfs.runForward()
		go mfs.runCounter()
	}
	go func() {
		for inEntry := range inChan {
			if len(fwdAll) > 0 {
				for _, shipper := range fwdAll {
					select {
					case shipper.ForwardInChan <- inEntry:
						//pass
					default:
						shipper.PerfStats.Dropped++
					}
				}
			}
			if shippers, ok := outputMap[inEntry.EventType]; ok {
				for _, shipper := range shippers {
					select {
					case shipper.ForwardInChan <- inEntry:
						//pass
					default:
						shipper.PerfStats.Dropped++
					}
				}
			}
		}
	}()
}

// SubmitStats registers a PerformanceStatsEncoder for runtime stats submission.
func (m *MultiForwardConfiguration) SubmitStats(sc *util.PerformanceStatsEncoder) {
	m.StatsEncoder = sc
}
