package processing

// DCSO FEVER
// Copyright (c) 2020, 2021, DCSO GmbH

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"regexp"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"
	log "github.com/sirupsen/logrus"
)

var (
	// match 24 hour local time string, separated by colon
	injectTimeRegex = regexp.MustCompile(`^(([01][0-9])|(2[0-3])):[0-5][0-9]$`)
	// We pick this value as a tick interval to check the time against the list
	// of times to send heartbeats at. We check once per minute as that is the
	// resolution of the specified times as well.
	injectTimeCheckTick = 1 * time.Minute
)

// HeartbeatInjector regularly adds a date-based pseudo-event to the forwarded
// event stream.
type HeartbeatInjector struct {
	SensorID       string
	Times          []string
	AlertTimes     []string
	CloseChan      chan bool
	Logger         *log.Entry
	ForwardHandler Handler
}

// MakeHeartbeatInjector creates a new HeartbeatInjector.
func MakeHeartbeatInjector(forwardHandler Handler, injectTimes []string, alertTimes []string) (*HeartbeatInjector, error) {
	sensorID, err := util.GetSensorID()
	if err != nil {
		return nil, err
	}
	for _, v := range injectTimes {
		if !injectTimeRegex.Match([]byte(v)) {
			return nil, fmt.Errorf("invalid time specification in heartbeat injector config: '%s'", v)
		}
	}
	for _, v := range alertTimes {
		if !injectTimeRegex.Match([]byte(v)) {
			return nil, fmt.Errorf("invalid alert time specification in heartbeat injector config: '%s'", v)
		}
	}
	a := &HeartbeatInjector{
		ForwardHandler: forwardHandler,
		Logger: log.WithFields(log.Fields{
			"domain": "heartbeat_injector",
		}),
		Times:      injectTimes,
		AlertTimes: alertTimes,
		CloseChan:  make(chan bool),
		SensorID:   sensorID,
	}
	return a, nil
}

func makeHeartbeatEvent(eventType string) types.Entry {
	now := time.Now()
	entry := types.Entry{
		SrcIP:     "192.0.2.1",
		SrcPort:   int64(rand.Intn(60000) + 1025),
		DestIP:    "192.0.2.2",
		DestPort:  80,
		Timestamp: time.Now().Format(types.SuricataTimestampFormat),
		EventType: eventType,
		Proto:     "TCP",
		HTTPHost: fmt.Sprintf("test-%d-%02d-%02d.vast",
			now.Year(), now.Month(), now.Day()),
		HTTPUrl:    "/just-visiting",
		HTTPMethod: "GET",
	}
	eve := types.EveEvent{
		Timestamp: &types.SuriTime{
			Time: time.Now().UTC(),
		},
		EventType: entry.EventType,
		SrcIP:     entry.SrcIP,
		SrcPort:   int(entry.SrcPort),
		DestIP:    entry.DestIP,
		DestPort:  int(entry.DestPort),
		Proto:     entry.Proto,
		HTTP: &types.HTTPEvent{
			Hostname:        entry.HTTPHost,
			URL:             entry.HTTPUrl,
			HTTPMethod:      entry.HTTPMethod,
			HTTPUserAgent:   "FEVER",
			Status:          200,
			Protocol:        "HTTP/1.1",
			Length:          42,
			HTTPContentType: "text/html",
		},
	}
	if eventType == "alert" {
		eve.Alert = &types.AlertEvent{
			Action:    "allowed",
			Category:  "Not Suspicious Traffic",
			Signature: "DCSO FEVER TEST alert",
		}
		entry.HTTPHost = "testalert.fever"
		eve.HTTP.Hostname = entry.HTTPHost
	}
	json, err := json.Marshal(eve)
	if err != nil {
		log.Warn(err)
	} else {
		entry.JSONLine = string(json)
	}
	return entry
}

// Run starts the background service.
func (a *HeartbeatInjector) Run() {
	go func() {
		for {
			select {
			case <-a.CloseChan:
				return
			default:
				curTime := time.Now().Format("15:04")
				for _, timeVal := range a.Times {
					if curTime == timeVal {
						ev := makeHeartbeatEvent("http")
						a.Logger.Infof("creating heartbeat HTTP event for %s: %s",
							curTime, string(ev.JSONLine))
						a.ForwardHandler.Consume(&ev)
					}
				}
				for _, timeVal := range a.AlertTimes {
					if curTime == timeVal {
						ev := makeHeartbeatEvent("alert")
						a.Logger.Infof("creating heartbeat alert event for %s: %s",
							curTime, string(ev.JSONLine))
						a.ForwardHandler.Consume(&ev)
					}
				}
				time.Sleep(injectTimeCheckTick)
			}
		}
	}()
}

// Stop causes the service to cease the background work.
func (a *HeartbeatInjector) Stop() {
	close(a.CloseChan)
}
