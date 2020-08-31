package input

// DCSO FEVER
// Copyright (c) 2020, DCSO GmbH

import (
	"bufio"
	"net"
	"os"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	log "github.com/sirupsen/logrus"
)

// StdinInput is an Input reading JSON EVE input from a Unix socket.
type StdinInput struct {
	EventChan     chan types.Entry
	Verbose       bool
	Running       bool
	InputListener net.Listener
	StopChan      chan bool
	StoppedChan   chan bool
}

// GetName returns a printable name for the input
func (si *StdinInput) GetName() string {
	return "Stdin input"
}

func (si *StdinInput) handleStdinStream() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		json := scanner.Bytes()
		e, err := util.ParseJSON(json)
		if err != nil {
			log.Error(err, string(json[:]))
			continue
		}
		si.EventChan <- e
	}
	close(si.EventChan)
}

// MakeStdinInput returns a new StdinInput reading from stdin and writing
// parsed events to outChan.
func MakeStdinInput(outChan chan types.Entry) *StdinInput {
	si := &StdinInput{
		EventChan: outChan,
		Verbose:   false,
		StopChan:  make(chan bool),
	}
	return si
}

// Run starts the StdinInput
func (si *StdinInput) Run() {
	if !si.Running {
		si.Running = true
		si.StopChan = make(chan bool)
		go si.handleStdinStream()
	}
}

// Stop causes the StdinInput to stop reading from stdin and close all
// associated channels, including the passed notification channel.
func (si *StdinInput) Stop(stoppedChan chan bool) {
	if si.Running {
		si.StoppedChan = stoppedChan
		si.Running = false
		close(stoppedChan)
	}
}

// SetVerbose sets the input's verbosity level
func (si *StdinInput) SetVerbose(verbose bool) {
	si.Verbose = verbose
}
