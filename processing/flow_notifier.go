package processing

// DCSO FEVER
// Copyright (c) 2020, DCSO GmbH

import (
	"github.com/DCSO/fever/types"
)

// FlowNotifier is a handler that just passes flow events on a
// given channel once encountered.
type FlowNotifier struct {
	FlowNotifyChan chan types.Entry
}

// MakeFlowNotifier creates a new FlowNotifier.
func MakeFlowNotifier(outChan chan types.Entry) *FlowNotifier {
	notifier := &FlowNotifier{
		FlowNotifyChan: outChan,
	}
	return notifier
}

// Consume processes an Entry, emitting an Entry on the output
// channel
func (n *FlowNotifier) Consume(e *types.Entry) error {
	n.FlowNotifyChan <- *e
	return nil
}

// GetName returns the name of the handler
func (n *FlowNotifier) GetName() string {
	return "Flow notifier"
}

// GetEventTypes returns a slice of event type strings that this handler
// should be applied to -- flow in this case.
func (n *FlowNotifier) GetEventTypes() []string {
	return []string{"flow"}
}
