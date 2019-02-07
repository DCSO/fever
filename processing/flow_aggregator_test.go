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
)

const (
	numOfTestFlowItems = 200000
)

func makeFlowEvent() types.Entry {
	e := types.Entry{
		SrcIP:         fmt.Sprintf("10.0.0.%d", rand.Intn(250)),
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

func TestFlowAggregator(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	outChan := make(chan types.Entry)
	feedWaitChan := make(chan bool)
	closeChan := make(chan bool)

	f := MakeFlowAggregator(1*time.Second, outChan)
	var procFlowsLock sync.Mutex
	var processedFlows int
	var eTotalPktsToClient int64
	var eTotalPktsToServer int64
	var eTotalBytesToClient int64
	var eTotalBytesToServer int64
	var rTotalPktsToClient int64
	var rTotalPktsToServer int64
	var rTotalBytesToClient int64
	var rTotalBytesToServer int64

	go func(pc *int64, ps *int64, bc *int64, bs *int64) {
		for {
			select {
			case e := <-outChan:
				var out struct {
					SrcPort []int `json:"src_port"`
					Flow    struct {
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

				// we count the source ports to determine the number of
				// aggregated flows
				procFlowsLock.Lock()
				processedFlows += len(out.SrcPort)
				procFlowsLock.Unlock()

				*bc += out.Flow.BytesToClient
				*bs += out.Flow.BytesToServer
				*pc += out.Flow.PktsToClient
				*ps += out.Flow.PktsToServer
			case <-closeChan:
				close(feedWaitChan)
				return
			}
		}
	}(&rTotalPktsToClient, &rTotalPktsToServer, &rTotalBytesToClient,
		&rTotalBytesToServer)

	f.Run()

	for i := 0; i < numOfTestFlowItems; i++ {
		ev := makeFlowEvent()
		eTotalBytesToClient += ev.BytesToClient
		eTotalBytesToServer += ev.BytesToServer
		eTotalPktsToClient += ev.PktsToClient
		eTotalPktsToServer += ev.PktsToServer
		f.Consume(&ev)
	}

	go func() {
		for {
			procFlowsLock.Lock()
			if processedFlows == numOfTestFlowItems {
				procFlowsLock.Unlock()
				break
			}
			procFlowsLock.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
		close(closeChan)
	}()

	<-feedWaitChan

	consumeWaitChan := make(chan bool)
	f.Stop(consumeWaitChan)
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
	dbChan := make(chan types.Entry, numOfTestFlowItems)
	feedWaitChan := make(chan bool)
	closeChan := make(chan bool)

	f := MakeFlowAggregator(1*time.Second, outChan)

	var procFlowsLock sync.Mutex
	var processedFlows int
	var eTotalPktsToClient int64
	var eTotalPktsToServer int64
	var eTotalBytesToClient int64
	var eTotalBytesToServer int64
	var rTotalPktsToClient int64
	var rTotalPktsToServer int64
	var rTotalBytesToClient int64
	var rTotalBytesToServer int64

	go func(pc *int64, ps *int64, bc *int64, bs *int64) {
		for {
			select {
			case e := <-outChan:
				var out struct {
					SrcPort []int `json:"src_port"`
					Flow    struct {
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

				// we count the source ports to determine the number of
				// aggregated flows
				procFlowsLock.Lock()
				processedFlows += len(out.SrcPort)
				procFlowsLock.Unlock()

				*bc += out.Flow.BytesToClient
				*bs += out.Flow.BytesToServer
				*pc += out.Flow.PktsToClient
				*ps += out.Flow.PktsToServer
			case <-closeChan:
				close(feedWaitChan)
				return
			}
		}
	}(&rTotalPktsToClient, &rTotalPktsToServer, &rTotalBytesToClient,
		&rTotalBytesToServer)

	d := MakeHandlerDispatcher(dbChan)
	d.RegisterHandler(f)
	f.Run()

	for i := 0; i < numOfTestFlowItems; i++ {
		ev := makeFlowEvent()
		eTotalBytesToClient += ev.BytesToClient
		eTotalBytesToServer += ev.BytesToServer
		eTotalPktsToClient += ev.PktsToClient
		eTotalPktsToServer += ev.PktsToServer
		d.Dispatch(&ev)
	}

	go func() {
		for {
			procFlowsLock.Lock()
			if processedFlows == numOfTestFlowItems {
				procFlowsLock.Unlock()
				break
			}
			procFlowsLock.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
		close(closeChan)
	}()

	<-feedWaitChan
	consumeWaitChan := make(chan bool)
	f.Stop(consumeWaitChan)
	<-consumeWaitChan

	if len(dbChan) != numOfTestFlowItems {
		t.Fatalf("not all input events forwarded: %d", len(dbChan))
	}
	close(dbChan)

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
