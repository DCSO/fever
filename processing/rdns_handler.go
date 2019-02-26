package processing

// DCSO FEVER
// Copyright (c) 2019, DCSO GmbH

import (
	"sync"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	log "github.com/sirupsen/logrus"
)

// RDNSHandler is a handler that enriches events with reverse DNS
// information looked up on the sensor, for both source and destination
// IP addresses.
type RDNSHandler struct {
	sync.Mutex
	Logger    *log.Entry
	HostNamer *util.HostNamer
}

// MakeRDNSHandler returns a new RDNSHandler, backed by the passed HostNamer.
func MakeRDNSHandler(hn *util.HostNamer) *RDNSHandler {
	rh := &RDNSHandler{
		Logger: log.WithFields(log.Fields{
			"domain": "rdns",
		}),
		HostNamer: hn,
	}
	return rh
}

// Consume processes an Entry and enriches it
func (a *RDNSHandler) Consume(e *types.Entry) error {
	var err error
	var res []string
	if e.SrcIP != "" {
		res, err = a.HostNamer.GetHostname(e.SrcIP)
		if err == nil {
			e.SrcHosts = res
		}
	}
	if e.DestIP != "" {
		res, err = a.HostNamer.GetHostname(e.DestIP)
		if err == nil {
			e.DestHosts = res
		}
	}
	return nil
}

// GetName returns the name of the handler
func (a *RDNSHandler) GetName() string {
	return "reverse DNS handler"
}

// GetEventTypes returns a slice of event type strings that this handler
// should be applied to
func (a *RDNSHandler) GetEventTypes() []string {
	return []string{"http", "dns", "tls", "smtp", "flow", "ssh", "tls", "smb", "alert"}
}
