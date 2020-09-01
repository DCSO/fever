package util

// DCSO FEVER
// Copyright (c) 2020, DCSO GmbH

import (
	"fmt"

	"github.com/DCSO/fever/types"
)

// AlertJSONProviderHTTPURL is an AlertJSONProvider for HTTP URL matches.
type AlertJSONProviderHTTPURL struct{}

// GetAlertJSON returns the "alert" subobject for an alert EVE event.
func (a AlertJSONProviderHTTPURL) GetAlertJSON(inputEvent types.Entry,
	prefix string, ioc string) ([]byte, error) {
	v := fmt.Sprintf("%s | %s | %s", inputEvent.HTTPMethod, inputEvent.HTTPHost,
		inputEvent.HTTPUrl)
	return GenericGetAlertObjForIoc(inputEvent, prefix, v,
		"%s Possibly bad HTTP URL: %s")
}

// AlertJSONProviderHTTPHost is an AlertJSONProvider for HTTP Host header
// matches.
type AlertJSONProviderHTTPHost struct{}

// GetAlertJSON returns the "alert" subobject for an alert EVE event.
func (a AlertJSONProviderHTTPHost) GetAlertJSON(inputEvent types.Entry,
	prefix string, ioc string) ([]byte, error) {
	return GenericGetAlertObjForIoc(inputEvent, prefix, ioc,
		"%s Possibly bad HTTP host: %s")
}

// AlertJSONProviderDNSReq is an AlertJSONProvider for DNS request matches.
type AlertJSONProviderDNSReq struct{}

// GetAlertJSON returns the "alert" subobject for an alert EVE event.
func (a AlertJSONProviderDNSReq) GetAlertJSON(inputEvent types.Entry,
	prefix string, ioc string) ([]byte, error) {
	return GenericGetAlertObjForIoc(inputEvent, prefix, ioc,
		"%s Possibly bad DNS lookup to %s")
}

// AlertJSONProviderDNSResp is an AlertJSONProvider for DNS response matches.
type AlertJSONProviderDNSResp struct{}

// GetAlertJSON returns the "alert" subobject for an alert EVE event.
func (a AlertJSONProviderDNSResp) GetAlertJSON(inputEvent types.Entry,
	prefix string, ioc string) ([]byte, error) {
	return GenericGetAlertObjForIoc(inputEvent, prefix, ioc,
		"%s Possibly bad DNS response for %s")
}

// AlertJSONProviderTLSSNI is an AlertJSONProvider for TLS SNI matches.
type AlertJSONProviderTLSSNI struct{}

// GetAlertJSON returns the "alert" subobject for an alert EVE event.
func (a AlertJSONProviderTLSSNI) GetAlertJSON(inputEvent types.Entry,
	prefix string, ioc string) ([]byte, error) {
	return GenericGetAlertObjForIoc(inputEvent, prefix, ioc,
		"%s Possibly bad TLS SNI: %s")
}
