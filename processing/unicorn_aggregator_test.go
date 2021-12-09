package processing

// DCSO FEVER
// Copyright (c) 2017, 2019, DCSO GmbH

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/DCSO/fever/types"
	log "github.com/sirupsen/logrus"
)

func makeUnicornFlowEvent() types.Entry {
	e := types.Entry{
		SrcIP:         fmt.Sprintf("10.%d.%d.%d", rand.Intn(250), rand.Intn(250), rand.Intn(250)),
		SrcPort:       []int64{1, 2, 3, 4, 5}[rand.Intn(5)],
		DestIP:        fmt.Sprintf("10.0.0.%d", rand.Intn(250)),
		DestPort:      []int64{11, 12, 13, 14, 15}[rand.Intn(5)],
		Timestamp:     time.Now().Format(types.SuricataTimestampFormat),
		EventType:     "flow",
		Proto:         "TCP",
		BytesToClient: int64(rand.Intn(10000)),
		BytesToServer: int64(rand.Intn(10000)),
		PktsToClient:  int64(rand.Intn(100)),
		PktsToServer:  int64(rand.Intn(100)),
	}
	jsonBytes, _ := json.Marshal(e)
	e.JSONLine = string(jsonBytes)
	return e
}

type testSubmitter struct {
	DataLock sync.Mutex
	Data     []string
}

func (s *testSubmitter) Submit(in []byte, key string, contentType string) {
	s.DataLock.Lock()
	defer s.DataLock.Unlock()
	s.Data = append(s.Data, string(in))
}

func (s *testSubmitter) SubmitWithHeaders(in []byte, key string, contentType string, hdr map[string]string) {
	s.Submit(in, key, contentType)
}

func (s *testSubmitter) GetNumberSubmissions() int {
	s.DataLock.Lock()
	defer s.DataLock.Unlock()
	return len(s.Data)
}

func (s *testSubmitter) GetTotalAggs() int {
	s.DataLock.Lock()
	defer s.DataLock.Unlock()
	totalTuples := make(map[string](int))
	for _, data := range s.Data {
		var agg UnicornAggregate
		err := json.Unmarshal([]byte(data), &agg)
		if err != nil {
			log.Fatalf("error parsing JSON: %s", err.Error())
		}
		for k := range agg.FlowTuples {
			totalTuples[k]++
		}
	}
	return len(totalTuples)
}

func (s *testSubmitter) GetFlowTuples() map[string](map[string]int64) {
	s.DataLock.Lock()
	defer s.DataLock.Unlock()
	allTuples := make(map[string](map[string]int64))
	for _, data := range s.Data {
		var agg UnicornAggregate
		err := json.Unmarshal([]byte(data), &agg)
		if err != nil {
			log.Fatalf("error parsing JSON: %s", err.Error())
		}
		for k := range agg.FlowTuples {
			if _, ok := allTuples[k]; !ok {
				allTuples[k] = make(map[string]int64)
			}
			allTuples[k]["count"] += agg.FlowTuples[k]["count"]
		}
	}
	return allTuples
}

func (s *testSubmitter) UseCompression() {}

func (s *testSubmitter) Finish() {}

func TestUnicornAggregatorNoSubmission(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	dsub := &testSubmitter{
		Data: make([]string, 0),
	}
	f := MakeUnicornAggregator(dsub, 100*time.Millisecond, false)
	f.Run()

	time.Sleep(1 * time.Second)

	consumeWaitChan := make(chan bool)
	f.Stop(consumeWaitChan)
	<-consumeWaitChan

	if dsub.GetNumberSubmissions() == 0 {
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
	f := MakeUnicornAggregator(dsub, 500*time.Millisecond, false)
	f.Run()

	createdFlows := make(map[string]int)
	for i := 0; i < 200000; i++ {
		ev := makeUnicornFlowEvent()
		if ev.BytesToClient > 0 {
			key := fmt.Sprintf("%s_%s_%d", ev.SrcIP, ev.DestIP, ev.DestPort)
			createdFlows[key]++
		}
		f.Consume(&ev)
	}

	for {
		if dsub.GetTotalAggs() < len(createdFlows) {
			log.Debug(dsub.GetTotalAggs())
			time.Sleep(100 * time.Millisecond)
		} else {
			break
		}
	}

	consumeWaitChan := make(chan bool)
	f.Stop(consumeWaitChan)
	<-consumeWaitChan

	if len(dsub.Data) == 0 {
		t.Fatalf("collected aggregations are empty")
	}

	log.Info(dsub.GetTotalAggs(), len(createdFlows), len(dsub.Data))

	var totallen int
	for _, v := range dsub.Data {
		totallen += len(v)
	}
	if totallen == 0 {
		t.Fatalf("length of collected aggregations is zero")
	}

	if dsub.GetTotalAggs() != len(createdFlows) {
		t.Fatalf("unexpected number of flow aggregates: %d/%d", dsub.GetTotalAggs(),
			len(createdFlows))
	}

	for k, v := range dsub.GetFlowTuples() {
		if _, ok := createdFlows[k]; !ok {
			t.Fatalf("missing flow aggregate: %s", k)
		}
		if v["count"] != int64(createdFlows[k]) {
			t.Fatalf("unexpected number of flows for %s: %d/%d",
				k, v["count"], createdFlows[k])
		}
	}
}

func TestUnicornAggregatorWithTestdata(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	dsub := &testSubmitter{
		Data: make([]string, 0),
	}
	f := MakeUnicornAggregator(dsub, 500*time.Millisecond, false)
	f.EnableTestFlow("1.2.3.4", "5.6.7.8", 33333)
	f.Run()

	for {
		if dsub.GetTotalAggs() < 1 {
			log.Debug(dsub.GetTotalAggs())
			time.Sleep(100 * time.Millisecond)
		} else {
			break
		}
	}

	consumeWaitChan := make(chan bool)
	f.Stop(consumeWaitChan)
	<-consumeWaitChan

	var d UnicornAggregate

	err := json.Unmarshal([]byte(dsub.Data[0]), &d)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := d.FlowTuples["1.2.3.4_5.6.7.8_33333"]; ok {
		if val, ok := v["count"]; ok {
			if val != 20 {
				t.Fatalf("wrong value: %v", val)
			}
		}
		if val, ok := v["total_bytes_toclient"]; ok {
			if val != 23 {
				t.Fatalf("wrong value: %v", val)
			}
		}
		if val, ok := v["total_bytes_toserver"]; ok {
			if val != 42 {
				t.Fatalf("wrong value: %v", val)
			}
		}
	} else {
		t.Fatalf("missing key in map: %v", d.FlowTuples)
	}

}

func TestUnicornAggregatorWithDispatch(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	dsub := &testSubmitter{
		Data: make([]string, 0),
	}
	f := MakeUnicornAggregator(dsub, 500*time.Millisecond, false)
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
	for i := 0; i < 200000; i++ {
		ev := makeUnicornFlowEvent()
		if ev.BytesToClient > 0 {
			key := fmt.Sprintf("%s_%s_%d", ev.SrcIP, ev.DestIP, ev.DestPort)
			createdFlows[key]++
		}
		d.Dispatch(&ev)
	}

	for {
		if dsub.GetTotalAggs() < len(createdFlows) {
			log.Debug(dsub.GetTotalAggs())
			time.Sleep(100 * time.Millisecond)
		} else {
			break
		}
	}

	consumeWaitChan := make(chan bool)
	f.Stop(consumeWaitChan)
	close(outChan)
	<-feedWaitChan
	<-consumeWaitChan

	if len(dsub.Data) == 0 {
		t.Fatalf("collected aggregations are empty")
	}

	log.Info(dsub.GetTotalAggs(), len(createdFlows), len(dsub.Data))

	var totallen int
	for _, v := range dsub.Data {
		totallen += len(v)
	}
	if totallen == 0 {
		t.Fatalf("length of collected aggregations is zero")
	}

	if dsub.GetTotalAggs() != len(createdFlows) {
		t.Fatalf("unexpected number of flow aggregates: %d/%d", dsub.GetTotalAggs(),
			len(createdFlows))
	}

	for k, v := range dsub.GetFlowTuples() {
		if _, ok := createdFlows[k]; !ok {
			t.Fatalf("missing flow aggregate: %s", k)
		}
		if v["count"] != int64(createdFlows[k]) {
			t.Fatalf("unexpected number of flows for %s: %d/%d",
				k, v["count"], createdFlows[k])
		}
	}
}
