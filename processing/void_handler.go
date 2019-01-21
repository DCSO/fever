package processing

// DCSO FEVER
// Copyright (c) 2019, DCSO GmbH

import (
	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	log "github.com/sirupsen/logrus"
)

// VoidHandler is a handler that does nothing.
type VoidHandler struct {
	Logger *log.Entry
}

// MakeVoidHandler creates a new forwarding handler
func MakeVoidHandler() *VoidHandler {
	fh := &VoidHandler{
		Logger: log.WithFields(log.Fields{
			"domain": "forward",
		}),
	}
	return fh
}

// Consume processes an Entry and discards it
func (fh *VoidHandler) Consume(e *types.Entry) error {
	_ = e
	return nil
}

// GetName returns the name of the handler
func (fh *VoidHandler) GetName() string {
	return "Void forwarding handler"
}

// GetEventTypes returns a slice of event type strings that this handler
// should be applied to
func (fh *VoidHandler) GetEventTypes() []string {
	if util.ForwardAllEvents {
		return []string{"*"}
	}
	return util.GetAllowedTypes()
}
