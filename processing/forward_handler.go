package processing

// DCSO FEVER
// Copyright (c) 2017, 2020, DCSO GmbH

import (
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	log "github.com/sirupsen/logrus"
)

// ForwardHandler is a handler that processes events by writing their JSON
// representation into a UNIX socket. This is limited by a list of allowed
// event types to be forwarded.
type ForwardHandler struct {
	Logger            *log.Entry
	DoRDNS            bool
	RDNSHandler       *RDNSHandler
	AddedFields       string
	ContextCollector  *ContextCollector
	StenosisIface     string
	StenosisConnector *StenosisConnector
	FlowNotifyChan    chan types.Entry
	MultiFwdChan      chan types.Entry
	Running           bool
	Lock              sync.Mutex
}

// MakeForwardHandler creates a new forwarding handler
func MakeForwardHandler(multiFwdChan chan types.Entry) *ForwardHandler {
	fh := &ForwardHandler{
		Logger: log.WithFields(log.Fields{
			"domain": "forward",
		}),
		MultiFwdChan: multiFwdChan,
	}
	return fh
}

// Consume processes an Entry and prepares it to be sent off to the
// forwarding sink
func (fh *ForwardHandler) Consume(inEntry *types.Entry) error {
	// make copy to pass on from here
	e := *inEntry
	// mark flow as relevant when alert is seen
	if GlobalContextCollector != nil && e.EventType == types.EventTypeAlert {
		GlobalContextCollector.Mark(string(e.FlowID))
	}
	// we also perform active rDNS enrichment if requested
	if fh.DoRDNS && fh.RDNSHandler != nil {
		err := fh.RDNSHandler.Consume(&e)
		if err != nil {
			return err
		}
	}
	// Replace the final brace `}` in the JSON with the prepared string to
	// add the 'added fields' defined in the config. I the length of this
	// string is 1 then there are no added fields, only a final brace '}'.
	// In this case we don't even need to modify the JSON string at all.
	if len(fh.AddedFields) > 1 {
		j := e.JSONLine
		l := len(j)
		j = j[:l-1]
		j += fh.AddedFields
		e.JSONLine = j
	}
	// if we use Stenosis, the Stenosis connector will take ownership of
	// alerts
	if fh.StenosisConnector != nil &&
		e.EventType == types.EventTypeAlert &&
		(fh.StenosisIface == "*" || e.Iface == fh.StenosisIface) {
		fh.StenosisConnector.Accept(&e)
	} else {
		fh.MultiFwdChan <- e
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
	return []string{"*"}
}

// EnableRDNS switches on reverse DNS enrichment for source and destination
// IPs in outgoing EVE events.
func (fh *ForwardHandler) EnableRDNS(expiryPeriod time.Duration) {
	fh.DoRDNS = true
	fh.RDNSHandler = MakeRDNSHandler(util.NewHostNamerRDNS(expiryPeriod, 2*expiryPeriod))
}

// AddFields enables the addition of a custom set of top-level fields to the
// forwarded JSON.
func (fh *ForwardHandler) AddFields(fields map[string]string) error {
	j := ""
	// We preprocess the JSON to be able to only use fast string operations
	// later. This code progressively builds a JSON snippet by adding JSON
	// key-value pairs for each added field, e.g. `, "foo":"bar"`.
	for k, v := range fields {
		// Escape the fields to make sure we do not mess up the JSON when
		// encountering weird symbols in field names or values.
		kval, err := util.EscapeJSON(k)
		if err != nil {
			fh.Logger.Warningf("cannot escape value: %s", v)
			return err
		}
		vval, err := util.EscapeJSON(v)
		if err != nil {
			fh.Logger.Warningf("cannot escape value: %s", v)
			return err
		}
		j += fmt.Sprintf(",%s:%s", kval, vval)
	}
	// We finish the list of key-value pairs with a final brace:
	// `, "foo":"bar"}`. This string can now just replace the final brace in a
	// given JSON string. If there were no added fields, we just leave the
	// output at the final brace.
	j += "}"
	fh.AddedFields = j
	return nil
}

// EnableStenosis connects the ForwardHandler with a Stenosis connector.
func (fh *ForwardHandler) EnableStenosis(endpoint string, timeout, timeBracket time.Duration,
	notifyChan chan types.Entry, cacheExpiry time.Duration, tlsConfig *tls.Config, iface string) (err error) {
	fh.StenosisConnector, err = MakeStenosisConnector(endpoint, timeout, timeBracket,
		notifyChan, fh.MultiFwdChan, cacheExpiry, tlsConfig)
	fh.StenosisIface = iface
	return
}
