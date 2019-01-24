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

func makeFlowEvent() types.Entry {
	e := types.Entry{
		SrcIP:         fmt.Sprintf("10.0.0.%d", rand.Intn(50)),
		SrcPort:       []int64{1, 2, 3, 4, 5}[rand.Intn(5)],
		DestIP:        fmt.Sprintf("10.0.0.%d", rand.Intn(50)),
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

func TestFlowAggregator(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	outChan := make(chan types.Entry)
	feedWaitChan := make(chan bool)
	f := MakeFlowAggregator(2*time.Second, outChan)
	var eTotalPktsToClient int64
	var eTotalPktsToServer int64
	var eTotalBytesToClient int64
	var eTotalBytesToServer int64
	var rTotalPktsToClient int64
	var rTotalPktsToServer int64
	var rTotalBytesToClient int64
	var rTotalBytesToServer int64

	go func(pc *int64, ps *int64, bc *int64, bs *int64) {
		for e := range outChan {
			var out struct {
				Flow struct {
					BytesToServer int64 `json:"bytes_toserver"`
					BytesToClient int64 `json:"bytes_toclient"`
					PktsToServer  int64 `json:"pkts_toserver"`
					PktsToClient  int64 `json:"pkts_toclient"`
				} `json:"flow"`
			}
			err := json.Unmarshal([]byte(e.JSONLine), &out)
			if err != nil {
				t.Fail()
			}
			*bc += out.Flow.BytesToClient
			*bs += out.Flow.BytesToServer
			*pc += out.Flow.PktsToClient
			*ps += out.Flow.PktsToServer
		}
		close(feedWaitChan)
	}(&rTotalPktsToClient, &rTotalPktsToServer, &rTotalBytesToClient,
		&rTotalBytesToServer)

	f.Run()

	for i := 0; i < 10000; i++ {
		ev := makeFlowEvent()
		eTotalBytesToClient += ev.BytesToClient
		eTotalBytesToServer += ev.BytesToServer
		eTotalPktsToClient += ev.PktsToClient
		eTotalPktsToServer += ev.PktsToServer
		f.Consume(&ev)
	}
	time.Sleep(5 * time.Second)
	consumeWaitChan := make(chan bool)
	f.Stop(consumeWaitChan)
	close(outChan)
	<-feedWaitChan
	<-consumeWaitChan

	if eTotalBytesToClient != rTotalBytesToClient {
		t.Fatalf("total bytes to client differ: %d/%d", eTotalBytesToClient,
			rTotalBytesToClient)
	}
	if eTotalBytesToServer != rTotalBytesToServer {
		t.Fatalf("total bytes to server differ: %d/%d", eTotalBytesToServer,
			rTotalBytesToServer)
	}
	if eTotalPktsToClient != rTotalPktsToClient {
		t.Fatalf("total pkts to client differ: %d/%d", eTotalPktsToClient,
			rTotalPktsToClient)
	}
	if eTotalPktsToServer != rTotalPktsToServer {
		t.Fatalf("total pkts to server differ: %d/%d", eTotalPktsToServer,
			rTotalPktsToServer)
	}
}

func TestFlowAggregatorWithDispatch(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	outChan := make(chan types.Entry)
	feedWaitChan := make(chan bool)
	f := MakeFlowAggregator(2*time.Second, outChan)
	var eTotalPktsToClient int64
	var eTotalPktsToServer int64
	var eTotalBytesToClient int64
	var eTotalBytesToServer int64
	var rTotalPktsToClient int64
	var rTotalPktsToServer int64
	var rTotalBytesToClient int64
	var rTotalBytesToServer int64

	go func(pc *int64, ps *int64, bc *int64, bs *int64) {
		for e := range outChan {
			var out struct {
				Flow struct {
					BytesToServer int64 `json:"bytes_toserver"`
					BytesToClient int64 `json:"bytes_toclient"`
					PktsToServer  int64 `json:"pkts_toserver"`
					PktsToClient  int64 `json:"pkts_toclient"`
				} `json:"flow"`
			}
			err := json.Unmarshal([]byte(e.JSONLine), &out)
			if err != nil {
				t.Fail()
			}
			*bc += out.Flow.BytesToClient
			*bs += out.Flow.BytesToServer
			*pc += out.Flow.PktsToClient
			*ps += out.Flow.PktsToServer
		}
		close(feedWaitChan)
	}(&rTotalPktsToClient, &rTotalPktsToServer, &rTotalBytesToClient,
		&rTotalBytesToServer)

	d := MakeHandlerDispatcher(outChan)
	d.RegisterHandler(f)
	f.Run()

	for i := 0; i < 10000; i++ {
		ev := makeFlowEvent()
		eTotalBytesToClient += ev.BytesToClient
		eTotalBytesToServer += ev.BytesToServer
		eTotalPktsToClient += ev.PktsToClient
		eTotalPktsToServer += ev.PktsToServer
		d.Dispatch(&ev)
	}
	time.Sleep(5 * time.Second)
	consumeWaitChan := make(chan bool)
	f.Stop(consumeWaitChan)
	close(outChan)
	<-feedWaitChan
	<-consumeWaitChan

	if eTotalBytesToClient != rTotalBytesToClient {
		t.Fatalf("total bytes to client differ: %d/%d", eTotalBytesToClient,
			rTotalBytesToClient)
	}
	if eTotalBytesToServer != rTotalBytesToServer {
		t.Fatalf("total bytes to server differ: %d/%d", eTotalBytesToServer,
			rTotalBytesToServer)
	}
	if eTotalPktsToClient != rTotalPktsToClient {
		t.Fatalf("total pkts to client differ: %d/%d", eTotalPktsToClient,
			rTotalPktsToClient)
	}
	if eTotalPktsToServer != rTotalPktsToServer {
		t.Fatalf("total pkts to server differ: %d/%d", eTotalPktsToServer,
			rTotalPktsToServer)
	}
}
