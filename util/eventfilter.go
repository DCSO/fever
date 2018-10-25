package util

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	log "github.com/sirupsen/logrus"
)

var filter map[string]bool

// ForwardAllEvents is set to true if the user has selected to skip event
// type filtering.
var ForwardAllEvents bool

// PrepareEventFilter registers the passed string array slice into the list of
// event types to be forwarded to the secondary processor.
func PrepareEventFilter(list []string, forwardall bool) {
	filter = make(map[string]bool)
	ForwardAllEvents = forwardall
	if ForwardAllEvents {
		log.WithFields(log.Fields{
			"domain": "forward",
		}).Info("forwarding all event types")
	}
	for _, s := range list {
		log.WithFields(log.Fields{
			"domain": "forward",
			"type":   s,
		}).Info("event type added")
		filter[s] = true
	}
}

// GetAllowedTypes returns a slice of strings with all forwarded types.
func GetAllowedTypes() []string {
	allowedTypes := make([]string, 0)
	for k := range filter {
		allowedTypes = append(allowedTypes, k)
	}
	return allowedTypes
}

// AllowType returns true if the event type indicated by the string t is allowed
// to be forwarded.
func AllowType(t string) bool {
	return (ForwardAllEvents || filter[t])
}
