package db

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"github.com/DCSO/fever/types"
)

// DummySlurper is a slurper that just consumes entries with no action.
type DummySlurper struct{}

// Run starts a DummySlurper.
func (s *DummySlurper) Run(eventchan chan types.Entry) {
	go func() {
		for range eventchan {
		}
	}()
}

// Finish is a null operation in the DummySlurper implementation.
func (s *DummySlurper) Finish() {
}
