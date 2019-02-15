package util

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"bytes"
	"strings"
	"sync"
	"time"

	"github.com/DCSO/fluxline"
	log "github.com/sirupsen/logrus"
)

// PerformanceStatsEncoder is a component to collect, encode and submit data
// to an InfluxDb via RabbitMQ.
type PerformanceStatsEncoder struct {
	sync.RWMutex
	Encoder       *fluxline.Encoder
	Buffer        bytes.Buffer
	Logger        *log.Entry
	Tags          map[string]string
	Submitter     StatsSubmitter
	SubmitPeriod  time.Duration
	LastSubmitted time.Time
	DummyMode     bool
}

// MakePerformanceStatsEncoder creates a new stats encoder, submitting via
// the given StatsSubmitter, with at least submitPeriod time between submissions.
// if dummyMode is set, then the result will be printed to stdout instead of
// submitting.
func MakePerformanceStatsEncoder(statsSubmitter StatsSubmitter,
	submitPeriod time.Duration, dummyMode bool) *PerformanceStatsEncoder {
	a := &PerformanceStatsEncoder{
		Logger: log.WithFields(log.Fields{
			"domain": "statscollect",
		}),
		Submitter:     statsSubmitter,
		DummyMode:     dummyMode,
		Tags:          make(map[string]string),
		LastSubmitted: time.Now(),
		SubmitPeriod:  submitPeriod,
	}
	a.Encoder = fluxline.NewEncoder(&a.Buffer)
	return a
}

// Submit encodes the data annotated with 'influx' tags in the passed struct and
// sends it to the configured submitter.
func (a *PerformanceStatsEncoder) Submit(val interface{}) {
	a.Lock()
	a.Buffer.Reset()
	err := a.Encoder.EncodeWithoutTypes(ToolName, val, a.Tags)
	if err != nil {
		if a.Logger != nil {
			a.Logger.WithFields(log.Fields{}).Warn(err)
		}
	}
	line := strings.TrimSpace(a.Buffer.String())
	if line == "" {
		a.Logger.WithFields(log.Fields{}).Warn("skipping empty influx line")
		a.Unlock()
		return
	}
	jsonString := []byte(line)
	a.Submitter.SubmitWithHeaders(jsonString, "", "text/plain", map[string]string{
		"database":         "telegraf",
		"retention_policy": "default",
	})
	a.Unlock()
}
