package processing

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"
)

// Handler is an interface describing the behaviour for a component to
// handle events parsed from EVE input.
type Handler interface {
	GetEventTypes() []string
	GetName() string
	Consume(*types.Entry) error
}

// ConcurrentHandler is an interface describing the behaviour for a component to
// handle events parsed from EVE input, while concurrently performing other
// actions, such as collecting, integrating and/or forwarding data.
type ConcurrentHandler interface {
	Handler
	Run()
	Stop(chan bool)
}

// StatsGeneratingHandler is an interface describing a Handler which also
// periodically outputs performance statistics using the provided
// PerformanceStatsEncoder.
type StatsGeneratingHandler interface {
	Handler
	SubmitStats(*util.PerformanceStatsEncoder)
}
