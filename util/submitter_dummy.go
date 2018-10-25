package util

// DCSO FEVER
// Copyright (c) 2018, DCSO GmbH

import (
	"unicode"

	log "github.com/sirupsen/logrus"
)

// DummySubmitter is a StatsSubmitter that just logs submissions without
// sending them over the network.
type DummySubmitter struct {
	Logger   *log.Entry
	SensorID string
}

func isASCIIPrintable(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// MakeDummySubmitter creates a new submitter just logging to the default log
// target.
func MakeDummySubmitter() (*DummySubmitter, error) {
	mySubmitter := &DummySubmitter{
		Logger: log.WithFields(log.Fields{
			"domain":    "submitter",
			"submitter": "dummy",
		}),
	}
	sensorID, err := GetSensorID()
	if err != nil {
		return nil, err
	}
	mySubmitter.SensorID = sensorID
	return mySubmitter, nil
}

// UseCompression enables gzip compression of submitted payloads (not
// applicable in this implementation).
func (s *DummySubmitter) UseCompression() {
	// pass
}

// Submit logs the rawData payload.
func (s *DummySubmitter) Submit(rawData []byte, key string, contentType string) {
	s.SubmitWithHeaders(rawData, key, contentType, nil)
}

// SubmitWithHeaders logs rawData payload, adding some extra key-value pairs to
// the header.
func (s *DummySubmitter) SubmitWithHeaders(rawData []byte, key string, contentType string, myHeaders map[string]string) {
	bytestring := string(rawData)
	if isASCIIPrintable(bytestring) {
		s.Logger.Info(bytestring)
	} else {
		s.Logger.Infof("%s (%s) - submitting non-printable byte array of length %d", key, contentType, len(rawData))
	}
}

// Finish is a no-op in this implementation.
func (s *DummySubmitter) Finish() {
	// pass
}
