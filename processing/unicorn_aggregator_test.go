package processing

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/DCSO/fever/types"
)

type testSubmitter struct {
	Data []string
}

func (s *testSubmitter) Submit(in []byte, key string, contentType string) {
	s.Data = append(s.Data, string(in))
}

func (s *testSubmitter) SubmitWithHeaders(in []byte, key string, contentType string, hdr map[string]string) {
	s.Submit(in, key, contentType)
}

func (s *testSubmitter) UseCompression() {}

func (s *testSubmitter) Finish() {}

func TestUnicornAggregatorNoSubmission(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	dsub := &testSubmitter{
		Data: make([]string, 0),
	}
	f := MakeUnicornAggregator(dsub, 2*time.Second, false)
	f.Run()

	time.Sleep(5 * time.Second)

	consumeWaitChan := make(chan bool)
	f.Stop(consumeWaitChan)
	<-consumeWaitChan

	if len(dsub.Data) == 0 {
		t.Fatalf("collected aggregations are empty")
	}

	var totallen int
	for _, v := range dsub.Data {
		totallen += len(v)
	}
	if totallen == 0 {
		t.Fatalf("length of collected aggregations is zero")
	}
}

func TestUnicornAggregator(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	dsub := &testSubmitter{
		Data: make([]string, 0),
	}
	f := MakeUnicornAggregator(dsub, 2*time.Second, false)
	f.Run()

	createdFlows := make(map[string]int)
	for i := 0; i < 10000; i++ {
		ev := makeFlowEvent()
		if ev.BytesToClient > 0 {
			key := fmt.Sprintf("%s_%s_%d", ev.SrcIP, ev.DestIP, ev.DestPort)
			createdFlows[key]++
		}
		f.Consume(&ev)
	}
	time.Sleep(5 * time.Second)

	consumeWaitChan := make(chan bool)
	f.Stop(consumeWaitChan)
	<-consumeWaitChan

	if len(dsub.Data) == 0 {
		t.Fatalf("collected aggregations are empty")
	}

	var totallen int
	for _, v := range dsub.Data {
		totallen += len(v)
	}
	if totallen == 0 {
		t.Fatalf("length of collected aggregations is zero")
	}

	var agg UnicornAggregate
	err := json.Unmarshal([]byte(dsub.Data[0]), &agg)
	if err != nil {
		t.Fatalf("error parsing JSON: %s", err.Error())
	}
	if len(agg.FlowTuples) != len(createdFlows) {
		t.Fatalf("unexpected number of flow aggregates: %d/%d", len(agg.FlowTuples),
			len(createdFlows))
	}

	for k, v := range agg.FlowTuples {
		if _, ok := createdFlows[k]; !ok {
			t.Fatalf("missing flow aggregate: %s", k)
		}
		if v["count"] != int64(createdFlows[k]) {
			t.Fatalf("unexpected number of flows for %s: %d/%d",
				k, v["count"], createdFlows[k])
		}
	}
}

func TestUnicornAggregatorWithDispatch(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	dsub := &testSubmitter{
		Data: make([]string, 0),
	}
	f := MakeUnicornAggregator(dsub, 2*time.Second, false)
	feedWaitChan := make(chan bool)
	outChan := make(chan types.Entry)

	go func() {
		for range outChan {
			// pass
		}
		close(feedWaitChan)
	}()

	d := MakeHandlerDispatcher(outChan)
	d.RegisterHandler(f)

	f.Run()

	createdFlows := make(map[string]int)
	for i := 0; i < 10000; i++ {
		ev := makeFlowEvent()
		if ev.BytesToClient > 0 {
			key := fmt.Sprintf("%s_%s_%d", ev.SrcIP, ev.DestIP, ev.DestPort)
			createdFlows[key]++
		}
		d.Dispatch(&ev)
	}
	time.Sleep(5 * time.Second)

	consumeWaitChan := make(chan bool)
	f.Stop(consumeWaitChan)
	close(outChan)
	<-feedWaitChan
	<-consumeWaitChan

	if len(dsub.Data) == 0 {
		t.Fatalf("collected aggregations are empty")
	}

	var totallen int
	for _, v := range dsub.Data {
		totallen += len(v)
	}
	if totallen == 0 {
		t.Fatalf("length of collected aggregations is zero")
	}

	var agg UnicornAggregate
	err := json.Unmarshal([]byte(dsub.Data[0]), &agg)
	if err != nil {
		t.Fatalf("error parsing JSON: %s", err.Error())
	}
	if len(agg.FlowTuples) != len(createdFlows) {
		t.Fatalf("unexpected number of flow aggregates: %d/%d", len(agg.FlowTuples),
			len(createdFlows))
	}

	for k, v := range agg.FlowTuples {
		if _, ok := createdFlows[k]; !ok {
			t.Fatalf("missing flow aggregate: %s", k)
		}
		if v["count"] != int64(createdFlows[k]) {
			t.Fatalf("unexpected number of flows for %s: %d/%d",
				k, v["count"], createdFlows[k])
		}
	}
}
