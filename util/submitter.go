package util

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

// StatsSubmitter is an interface for an entity that sends JSON data to an endpoint
type StatsSubmitter interface {
	Submit(rawData []byte, key string, contentType string)
	SubmitWithHeaders(rawData []byte, key string, contentType string, myHeaders map[string]string)
	UseCompression()
	Finish()
}
