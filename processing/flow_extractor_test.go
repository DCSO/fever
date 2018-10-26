package processing

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"github.com/NeowayLabs/wabbit"
	"github.com/NeowayLabs/wabbit/amqptest"
	"github.com/NeowayLabs/wabbit/amqptest/server"

	"github.com/DCSO/bloom"
	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"sync"
	"testing"
	"time"
)

func makeFlowExtractorEvent(ipv6 bool) types.Entry {

	protos := []string{"TCP", "UDP"}
	n := rand.Int() % len(protos)

	var srcIP, destIP string
	if !ipv6 {
		srcIP = fmt.Sprintf("10.0.0.%d", rand.Intn(50))
		destIP = fmt.Sprintf("10.0.0.%d", rand.Intn(50))
	} else {
		srcIP = fmt.Sprintf("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
		destIP = fmt.Sprintf("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	}

	e := types.Entry{
		SrcIP:         srcIP,
		SrcPort:       []int64{1, 2, 3, 4, 5}[rand.Intn(5)],
		DestIP:        destIP,
		DestPort:      []int64{11, 12, 13, 14, 15}[rand.Intn(5)],
		Timestamp:     time.Now().Format(types.SuricataTimestampFormat),
		EventType:     "flow",
		Proto:         protos[n],
		BytesToClient: int64(rand.Intn(10000)),
		BytesToServer: int64(rand.Intn(10000)),
		PktsToClient:  int64(rand.Intn(100)),
		PktsToServer:  int64(rand.Intn(100)),
	}
	return e
}

func makeBloomFilter() *bloom.BloomFilter {
	bf := bloom.Initialize(10000, 1e-10)
	for i := 0; i < 10000; i++ {
		bf.Add([]byte(fmt.Sprintf("10.0.0.%d", rand.Intn(50))))
	}
	bf.Add([]byte("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
	return &bf
}

func TestFlowExtractor(t *testing.T) {
	serverURL := "amqp://sensor:sensor@127.0.0.1:11111/%2f/"

	// start mock AMQP server
	fakeServer := server.NewServer(serverURL)
	fakeServer.Start()
	defer fakeServer.Stop()

	// set up consumer
	results := make([]string, 0)
	var resultsLock sync.Mutex
	c, err := util.NewConsumer(serverURL, "tdh.flows", "direct", "tdh.flows.testqueue",
		"", "", func(d wabbit.Delivery) {
			resultsLock.Lock()
			results = append(results, string(d.Body()))
			resultsLock.Unlock()
		})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Shutdown()

	nEvents := 10000

	// set up submitter
	submitter, err := util.MakeAMQPSubmitterWithReconnector(serverURL,
		"tdh.flows", true, func(url string) (wabbit.Conn, string, error) {
			var conn wabbit.Conn
			conn, err = amqptest.Dial(url)
			return conn, "direct", err
		})
	if err != nil {
		t.Fatal(err)
	}
	defer submitter.Finish()

	mla, err := MakeFlowExtractor(2*time.Second, 100, "", submitter)

	mla.BloomFilter = makeBloomFilter()

	if err != nil {
		t.Fatal(err)
	}

	mla.Run()

	expectedFlows := make([]types.Entry, 0)

	for i := 0; i < nEvents; i++ {
		ipv6 := false
		//we mix in some IPv6 packets...
		if rand.Intn(2) == 0 {
			ipv6 = true
		}
		ev := makeFlowExtractorEvent(ipv6)
		err := mla.Consume(&ev)
		if err != nil {
			t.Fatal(err)
		}
		if mla.BloomFilter.Check([]byte(ev.SrcIP)) || mla.BloomFilter.Check([]byte(ev.DestIP)) {
			expectedFlows = append(expectedFlows, ev)
		}
	}

	time.Sleep(3 * time.Second)

	flows := make([]types.FlowEvent, 0)

	resultsLock.Lock()
	for i := range results {
		result := results[i]
		buffer := bytes.NewBufferString(result)
		for {
			var fe types.FlowEvent
			err := fe.Unmarshal(buffer)
			if err != nil {
				break
			}
			flows = append(flows, fe)
		}
	}
	resultsLock.Unlock()
	if len(flows) != len(expectedFlows) {
		t.Fatalf("Error: Expected %d flows, got %d!", len(expectedFlows), len(flows))
	}

	for i := range flows {
		flow := flows[i]
		expectedEntry := expectedFlows[i]
		var expectedFlow types.FlowEvent
		expectedFlow.FromEntry(&expectedEntry)
		if !reflect.DeepEqual(flow, expectedFlow) {
			t.Errorf("Flows do not match!")

			if flow.Format != expectedFlow.Format {
				t.Errorf("Formats do not match!")
			}

			if flow.Timestamp != expectedFlow.Timestamp {
				t.Errorf("Timestamps do not match!")
			}

			if !bytes.Equal(flow.SrcIP, expectedFlow.SrcIP) {
				t.Errorf("Source IPs do not match!")
			}

			if !bytes.Equal(flow.DestIP, expectedFlow.DestIP) {
				t.Errorf("Destination IPs do not match!")
			}

			if flow.SrcPort != expectedFlow.SrcPort {
				t.Errorf("Source Ports do not match!")
			}

			if flow.DestPort != expectedFlow.DestPort {
				t.Errorf("Destination Ports do not match!")
			}

			if flow.Flags != expectedFlow.Flags {
				t.Errorf("Flags do not match!")
			}

			if flow.BytesToServer != expectedFlow.BytesToServer {
				t.Errorf("BytesToServer do not match!")
			}

			if flow.BytesToClient != expectedFlow.BytesToClient {
				t.Errorf("BytesToClient do not match!")
			}

			if flow.PktsToServer != expectedFlow.PktsToServer {
				t.Errorf("PktsToServer do not match!")
			}

			if flow.PktsToClient != expectedFlow.PktsToClient {
				t.Errorf("PktsToClient do not match!")
			}

		}
	}

}
