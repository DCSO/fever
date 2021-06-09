package input

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"bufio"
	"net"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	log "github.com/sirupsen/logrus"
)

// SocketInputPerfStats contains performance stats written to InfluxDB
// for monitoring.
type SocketInputPerfStats struct {
	SocketQueueLength  uint64 `influx:"input_queue_length"`
	SocketQueueDropped uint64 `influx:"input_queue_dropped"`
}

// SocketInput is an Input reading JSON EVE input from a Unix socket.
type SocketInput struct {
	EventChan         chan types.Entry
	Verbose           bool
	Running           bool
	InputListener     net.Listener
	StopChan          chan bool
	StoppedChan       chan bool
	DropIfChannelFull bool
	PerfStats         SocketInputPerfStats
	StatsEncoder      *util.PerformanceStatsEncoder
}

// GetName returns a printable name for the input
func (si *SocketInput) GetName() string {
	return "Socket input"
}

func (si *SocketInput) handleServerConnection() {
	for {
		select {
		case <-si.StopChan:
			close(si.StoppedChan)
			return
		default:
			var start time.Time
			var totalLen int

			si.InputListener.(*net.UnixListener).SetDeadline(time.Now().Add(1e9))
			c, err := si.InputListener.Accept()
			if nil != err {
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					continue
				}
				log.Info(err)
			}

			if si.Verbose {
				start = time.Now()
			}
			scanner := bufio.NewScanner(c)
			buf := make([]byte, 0, 32*1024*1024)
			scanner.Buffer(buf, 32*1024*1024)
			for {
				for scanner.Scan() {
					select {
					case <-si.StopChan:
						close(si.StoppedChan)
						return
					default:
						json := scanner.Bytes()
						totalLen += len(json)
						e, err := util.ParseJSON(json)
						if err != nil {
							log.Warn(err, string(json[:]))
							continue
						}
						if si.DropIfChannelFull {
							select {
							case si.EventChan <- e:
								// pass
							default:
								si.PerfStats.SocketQueueDropped++
							}
						} else {
							si.EventChan <- e
						}
					}
				}
				errRead := scanner.Err()
				if errRead == nil {
					break
				} else if errRead == bufio.ErrTooLong {
					log.Warn(errRead)
					scanner = bufio.NewScanner(c)
					scanner.Buffer(buf, 2*cap(buf))
				} else {
					log.Warn(errRead)
				}
			}

			if si.Verbose {
				elapsed := time.Since(start)
				log.WithFields(log.Fields{
					"size":        totalLen,
					"elapsedTime": elapsed,
				}).Info("connection handled")
			}
		}
	}
}

func (si *SocketInput) sendPerfStats() {
	start := time.Now()
	for {
		select {
		case <-si.StopChan:
			return
		default:
			// We briefly wake up once a second to check whether we are asked
			// to stop or whether it's time to submit stats. This is neglegible
			// in overhead but massively improves shutdown time, as a simple
			// time.Sleep() is non-interruptible by the stop channel.
			if time.Since(start) > perfStatsSendInterval {
				if si.StatsEncoder != nil {
					si.PerfStats.SocketQueueLength = uint64(len(si.EventChan))
					si.StatsEncoder.Submit(si.PerfStats)
				}
				start = time.Now()
			}
			time.Sleep(1 * time.Second)
		}
	}
}

// MakeSocketInput returns a new SocketInput reading from the Unix socket
// inputSocket and writing parsed events to outChan. If no such socket could be
// created for listening, the error returned is set accordingly.
func MakeSocketInput(inputSocket string,
	outChan chan types.Entry, bufDrop bool) (*SocketInput, error) {
	var err error
	si := &SocketInput{
		EventChan:         outChan,
		Verbose:           false,
		StopChan:          make(chan bool),
		DropIfChannelFull: bufDrop,
	}
	si.InputListener, err = net.Listen("unix", inputSocket)
	if err != nil {
		return nil, err
	}
	return si, err
}

// SubmitStats registers a PerformanceStatsEncoder for runtime stats submission.
func (si *SocketInput) SubmitStats(sc *util.PerformanceStatsEncoder) {
	si.StatsEncoder = sc
}

// Run starts the SocketInput
func (si *SocketInput) Run() {
	if !si.Running {
		si.Running = true
		si.StopChan = make(chan bool)
		go si.handleServerConnection()
		go si.sendPerfStats()
	}
}

// Stop causes the SocketInput to stop reading from the socket and close all
// associated channels, including the passed notification channel.
func (si *SocketInput) Stop(stoppedChan chan bool) {
	if si.Running {
		si.StoppedChan = stoppedChan
		close(si.StopChan)
		si.Running = false
	}
}

// SetVerbose sets the input's verbosity level
func (si *SocketInput) SetVerbose(verbose bool) {
	si.Verbose = verbose
}
