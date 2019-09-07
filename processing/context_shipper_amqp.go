package processing

// DCSO FEVER
// Copyright (c) 2019, DCSO GmbH

import (
	"encoding/json"
	"time"

	"github.com/DCSO/fever/util"

	log "github.com/sirupsen/logrus"
)

const (
	// ContextQueueLength is the length of the queue buffering incoming context
	// bundles to balance out potential transmission delays.
	ContextQueueLength = 100
)

// ContextChunk represents a collection of events for transmission via AMQP.
type ContextChunk struct {
	Timestamp time.Time     `json:"timestamp"`
	SensorID  string        `json:"sensor_id"`
	Events    []interface{} `json:"events"`
}

// ContextShipperAMQP is a ContextShipper that sends incoming context bundles to
// an AMQP exchange.
type ContextShipperAMQP struct {
	Submitter util.StatsSubmitter
	InChan    chan Context
	SensorID  string
}

// Start initiates the concurrent handling of incoming context bundles in the
// Shipper's input channel. It will stop automatically once this channel is
// closed.
func (cs *ContextShipperAMQP) Start(s util.StatsSubmitter) (chan<- Context, error) {
	var err error
	cs.Submitter = s
	cs.InChan = make(chan Context, ContextQueueLength)
	cs.SensorID, err = util.GetSensorID()
	if err != nil {
		return nil, err
	}

	go func() {
		for ctx := range cs.InChan {
			out := make([]interface{}, 0)
			for _, ctxItem := range ctx {
				var myItem interface{}
				err := json.Unmarshal([]byte(ctxItem), &myItem)
				if err != nil {
					log.Warnf("could not marshal event JSON: %s", string(ctxItem))
					continue
				}
				out = append(out, myItem)
			}
			chunk := ContextChunk{
				Timestamp: time.Now(),
				SensorID:  cs.SensorID,
				Events:    out,
			}
			json, err := json.Marshal(chunk)
			if err != nil {
				log.Warn(err)
				continue
			}
			s.Submit(json, "context", "application/json")
		}
	}()

	return cs.InChan, nil
}
