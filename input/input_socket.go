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

// SocketInput is an Input reading JSON EVE input from a Unix socket.
type SocketInput struct {
	EventChan     chan types.Entry
	Verbose       bool
	Running       bool
	InputListener net.Listener
	StopChan      chan bool
	StoppedChan   chan bool
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
						si.EventChan <- e
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

// MakeSocketInput returns a new SocketInput reading from the Unix socket
// inputSocket and writing parsed events to outChan. If no such socket could be
// created for listening, the error returned is set accordingly.
func MakeSocketInput(inputSocket string,
	outChan chan types.Entry) (*SocketInput, error) {
	var err error
	si := &SocketInput{
		EventChan: outChan,
		Verbose:   false,
		StopChan:  make(chan bool),
	}
	si.InputListener, err = net.Listen("unix", inputSocket)
	if err != nil {
		return nil, err
	}
	return si, err
}

// Run starts the SocketInput
func (si *SocketInput) Run() {
	if !si.Running {
		si.Running = true
		si.StopChan = make(chan bool)
		go si.handleServerConnection()
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
