package util

// DCSO FEVER
// Copyright (c) 2020, DCSO GmbH

import (
	"fmt"

	"github.com/DCSO/fever/types"

	"github.com/buger/jsonparser"
	log "github.com/sirupsen/logrus"
)

// ExtraModifier is a function type that describes a function that adds the
// appropriate `_extra` sub-object entries to a EVE-JSON event.
type ExtraModifier func(inputAlert *types.Entry, ioc string) error

// AlertJSONProvider is an interface describing a component that returns an
// `alert` JSON sub-object to use in an EVE-JSON event.
type AlertJSONProvider interface {
	// GetAlertJSON is a function that returns a byte slice containing the
	// JSON data for an `alert` EVE-JSON sub-object.
	GetAlertJSON(inputEvent types.Entry, prefix string, ioc string) ([]byte, error)
}

// Alertifier is a component that creates EVE-JSON alerts from arbitrary
// EVE-JSON events. It does this by cloning the original event and adding
// alert-specific fields, depending on the given ExtraModifier and a set of
// AlertJSONProviders, selectable using a string tag.
type Alertifier struct {
	alertPrefix   string
	extraModifier ExtraModifier
	matchTypes    map[string]AlertJSONProvider
}

// MakeAlertifier returns a new Alertifier, with no AlertJSONProviders set for
// any match types, but with the given alert prefix preconfigured.
// The alert prefix is a string that is prepended to all alert.signature values,
// as in "DCSO TIE-BLF" or "ETPRO CURRENT_EVENTS", etc.
func MakeAlertifier(prefix string) *Alertifier {
	a := &Alertifier{
		alertPrefix: prefix,
		matchTypes:  make(map[string]AlertJSONProvider),
	}
	return a
}

// RegisterMatchType associates a given AlertJSONProvider with a match type tag.
// It makes it callable in the MakeAlert() function in this Alertifier.
func (a *Alertifier) RegisterMatchType(matchTypeName string, mt AlertJSONProvider) {
	a.matchTypes[matchTypeName] = mt
}

// SetPrefix sets the signature prefix of the current Alertifier to the given
// string value.
func (a *Alertifier) SetPrefix(prefix string) {
	a.alertPrefix = prefix
}

// SetExtraModifier sets the _extra modifier of the current Alertifier to the
// passed function. Set it to nil to disable modification of the _extra
// sub-object.
func (a *Alertifier) SetExtraModifier(em ExtraModifier) {
	a.extraModifier = em
}

// MakeAlert generates a new Entry representing an `alert` event based on the
// given input metadata event. It uses the information from the Alertifier as
// well as the given IoC to craft an `alert` sub-object in the resulting
// alert, which is built by the AlertJSONProvider registered under the specified
// matchType.
func (a *Alertifier) MakeAlert(inputEvent types.Entry, ioc string,
	matchType string) (*types.Entry, error) {
	if v, ok := a.matchTypes[matchType]; ok {
		// clone the original event
		newEntry := inputEvent
		// set a new event type in Entry
		newEntry.EventType = "alert"
		// generate alert sub-object JSON
		val, err := v.GetAlertJSON(inputEvent, a.alertPrefix, ioc)
		if err != nil {
			return nil, err
		}
		// update JSON text
		l, err := jsonparser.Set([]byte(newEntry.JSONLine), val, "alert")
		if err != nil {
			return nil, err
		}
		newEntry.JSONLine = string(l)
		l, err = jsonparser.Set([]byte(newEntry.JSONLine),
			[]byte(`"alert"`), "event_type")
		if err != nil {
			return nil, err
		}
		newEntry.JSONLine = string(l)
		if a.extraModifier != nil {
			err = a.extraModifier(&newEntry, ioc)
			if err != nil {
				return nil, err
			}
		}
		return &newEntry, nil
	}
	return nil, fmt.Errorf("cannot create alert for metadata, unknown "+
		"matchtype '%s'", matchType)
}

// GenericGetAlertObjForIoc is a simple helper function that takes a format
// string with string ('%s') placeholders for the prefix and the IoC. It also
// sets basic other alert fields such as `category` and `action`.
func GenericGetAlertObjForIoc(inputEvent types.Entry,
	prefix string, ioc string, msg string) ([]byte, error) {
	sig := fmt.Sprintf(msg, prefix, ioc)
	val, err := EscapeJSON(sig)
	if err != nil {
		return nil, err
	}
	newAlertSubObj := "{}"
	if l, err := jsonparser.Set([]byte(newAlertSubObj), val, "signature"); err != nil {
		log.Warning(err)
	} else {
		newAlertSubObj = string(l)
	}
	if l, err := jsonparser.Set([]byte(newAlertSubObj),
		[]byte(`"Potentially Bad Traffic"`), "category"); err != nil {
		log.Warning(err)
	} else {
		newAlertSubObj = string(l)
	}
	if l, err := jsonparser.Set([]byte(newAlertSubObj),
		[]byte(`"allowed"`), "action"); err != nil {
		log.Warning(err)
	} else {
		newAlertSubObj = string(l)
	}
	return []byte(newAlertSubObj), err
}
