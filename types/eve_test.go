package types

// DCSO FEVER
// Copyright (c) 2019, DCSO GmbH

import (
	"encoding/json"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestEVERoundtripTimestamp(t *testing.T) {
	timeCmp, _ := time.Parse(time.RFC3339, "2019-08-06 13:30:01.690233 +0200 CEST")
	ee := EveEvent{
		Timestamp: &suriTime{
			Time: timeCmp,
		},
		EventType: "http",
		SrcIP:     "1.2.3.4",
		SrcPort:   2222,
		DestIP:    "3.4.5.6",
		DestPort:  80,
		Proto:     "tcp",
		HTTP: &HTTPEvent{
			Hostname: "test",
			URL:      "/",
		},
	}

	out, err := json.Marshal(ee)
	if err != nil {
		t.Error(err)
	}

	var inEVE EveEvent
	err = json.Unmarshal(out, &inEVE)
	if err != nil {
		t.Error(err)
	}

	if !inEVE.Timestamp.Time.Equal(ee.Timestamp.Time) {
		t.Fatalf("timestamp round-trip failed: %v <-> %v", inEVE.Timestamp, ee.Timestamp)
	} else {
		log.Info("timestamps ok")
	}
}
