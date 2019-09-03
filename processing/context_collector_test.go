package processing

// DCSO FEVER
// Copyright (c) 2019, DCSO GmbH

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/DCSO/fever/types"
	log "github.com/sirupsen/logrus"
)

func makeCCTestEvent(eType, flowID string) types.Entry {
	e := types.Entry{
		SrcIP:     fmt.Sprintf("10.%d.%d.%d", rand.Intn(250), rand.Intn(250), rand.Intn(250)),
		SrcPort:   []int64{1, 2, 3, 4, 5}[rand.Intn(5)],
		DestIP:    fmt.Sprintf("10.0.0.%d", rand.Intn(250)),
		DestPort:  []int64{11, 12, 13, 14, 15}[rand.Intn(5)],
		Timestamp: time.Now().Format(types.SuricataTimestampFormat),
		EventType: eType,
		Proto:     "TCP",
		FlowID:    flowID,
	}
	jsonBytes, _ := json.Marshal(e)
	e.JSONLine = string(jsonBytes)
	return e
}

func TestContextCollector(t *testing.T) {
	markedVals := make(map[string][]string)
	seenMarked := make(map[string][]string)
	dsub := func(entries Context, logger *log.Entry) error {
		for _, v := range entries {
			var parsed struct {
				FlowID string
			}
			err := json.Unmarshal([]byte(v), &parsed)
			if err != nil {
				t.Fatal(err)
			}
			seenMarked[parsed.FlowID] = append(seenMarked[parsed.FlowID], v)
		}
		return nil
	}
	cc := MakeContextCollector(dsub)

	nofReports := 0
	for i := 0; i < 10000; i++ {
		isMarked := (rand.Intn(20) < 1)
		flowID := fmt.Sprintf("%d", rand.Intn(10000000)+10000)
		if isMarked {
			nofReports++
			cc.Mark(flowID)
		}
		for j := 0; j < rand.Intn(200)+1; j++ {
			ev := makeCCTestEvent([]string{"http", "smb", "dns"}[rand.Intn(3)], flowID)
			if isMarked {
				markedVals[flowID] = append(markedVals[flowID], ev.JSONLine)
			}
			cc.Consume(&ev)
		}

		ev := makeCCTestEvent("flow", flowID)
		cc.Consume(&ev)
	}

	if len(markedVals) != len(seenMarked) {
		t.Fatalf("number of marked flows (%d) != number of results (%d)", len(markedVals), len(seenMarked))
	}

	if !reflect.DeepEqual(markedVals, seenMarked) {
		t.Fatal("contents of results and recorded metadata maps differ")
	}
}

func TestContextCollectorMissingFlowID(t *testing.T) {
	e := types.Entry{
		Timestamp: time.Now().Format(types.SuricataTimestampFormat),
		EventType: "stats",
	}
	jsonBytes, _ := json.Marshal(e)
	e.JSONLine = string(jsonBytes)

	count := 0

	dsub := func(entries Context, logger *log.Entry) error {
		count++
		return nil
	}
	cc := MakeContextCollector(dsub)

	cc.Consume(&e)

	if count != 0 {
		t.Fatalf("event with empty flow ID was considered")
	}

	flowID := "12345"
	cc.Mark(flowID)
	ev := makeCCTestEvent("dns", flowID)
	cc.Consume(&ev)
	ev = makeCCTestEvent("flow", flowID)
	cc.Consume(&ev)

	if count != 1 {
		t.Fatalf("wrong number of entries: %d", count)
	}
}
