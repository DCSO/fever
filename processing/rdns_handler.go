package processing

// DCSO FEVER
// Copyright (c) 2019, 2020, DCSO GmbH

import (
	"fmt"
	"net"
	"sync"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"
	"github.com/buger/jsonparser"

	log "github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"
)

// RDNSHandler is a handler that enriches events with reverse DNS
// information looked up on the sensor, for both source and destination
// IP addresses.
type RDNSHandler struct {
	sync.Mutex
	Logger            *log.Entry
	HostNamer         *util.HostNamer
	PrivateRanges     cidranger.Ranger
	PrivateRangesOnly bool
}

// MakeRDNSHandler returns a new RDNSHandler, backed by the passed HostNamer.
func MakeRDNSHandler(hn *util.HostNamer) *RDNSHandler {
	rh := &RDNSHandler{
		Logger: log.WithFields(log.Fields{
			"domain": "rdns",
		}),
		PrivateRanges: cidranger.NewPCTrieRanger(),
		HostNamer:     hn,
	}
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("cannot parse fixed private IP range %v", cidr)
		}
		rh.PrivateRanges.Insert(cidranger.NewBasicRangerEntry(*block))
	}
	return rh
}

// EnableOnlyPrivateIPRanges ensures that only private (RFC1918) IP ranges
// are enriched
func (a *RDNSHandler) EnableOnlyPrivateIPRanges() {
	a.PrivateRangesOnly = true
}

// Consume processes an Entry and enriches it
func (a *RDNSHandler) Consume(e *types.Entry) error {
	var res []string
	var err error
	var isPrivate bool

	if e.SrcIP != "" {
		ip := net.ParseIP(e.SrcIP)
		if ip != nil {
			isPrivate, err = a.PrivateRanges.Contains(ip)
			if err != nil {
				return err
			}
			if !a.PrivateRangesOnly || isPrivate {
				res, err = a.HostNamer.GetHostname(e.SrcIP)
				if err == nil {
					for i, v := range res {
						jsonparser.Set([]byte(e.JSONLine), []byte(v), "src_host", fmt.Sprintf("[%d]", i))
					}
				}
			}
		} else {
			log.Error("IP not valid")
		}
	}
	if e.DestIP != "" {
		ip := net.ParseIP(e.DestIP)
		if ip != nil {
			isPrivate, err = a.PrivateRanges.Contains(ip)
			if err != nil {
				return err
			}
			if !a.PrivateRangesOnly || isPrivate {
				res, err = a.HostNamer.GetHostname(e.DestIP)
				if err == nil {
					for i, v := range res {
						jsonparser.Set([]byte(e.JSONLine), []byte(v), "dest_host", fmt.Sprintf("[%d]", i))
					}
				}
			}
		} else {
			log.Error("IP not valid")
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
