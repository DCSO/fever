package db

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"github.com/DCSO/fever/types"
)

// Slurper is an interface for a worker that can be started (Run()) with a given
// channel delivering Entries, storing them in an associated data store.
// Finish() can be used to finalize any state.
// TODO implement proper start/stop (atm 'hard' stop by exit()ing)
type Slurper interface {
	Run(chan types.Entry)
	Finish()
}
