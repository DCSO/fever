package processing

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"fmt"
	"math/rand"
	"regexp"
	"testing"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"
	log "github.com/sirupsen/logrus"

	"github.com/NeowayLabs/wabbit"
	"github.com/NeowayLabs/wabbit/amqptest"
	"github.com/NeowayLabs/wabbit/amqptest/server"
)

type Test1Handler struct {
	Vals []string
}

func (h *Test1Handler) GetName() string {
	return "Test handler 1"
}

func (h *Test1Handler) GetEventTypes() []string {
	return []string{"dns"}
}

func (h *Test1Handler) Consume(e *types.Entry) error {
	h.Vals = append(h.Vals, e.JSONLine)
	return nil
}

type Test2Handler struct {
	Vals []string
}

func (h *Test2Handler) GetName() string {
	return "Test handler 2"
}

func (h *Test2Handler) GetEventTypes() []string {
	return []string{"http"}
}

func (h *Test2Handler) Consume(e *types.Entry) error {
	h.Vals = append(h.Vals, e.JSONLine)
	return nil
}

func TestHandlerDispatcherExampleHandler(t *testing.T) {
	outChan := make(chan types.Entry)
	closeChan := make(chan bool)
	defaultSelection := make([]string, 0)

	go func(closeChan chan bool, inChan chan types.Entry) {
		for v := range inChan {
			defaultSelection = append(defaultSelection, v.JSONLine)
		}
		close(closeChan)
	}(closeChan, outChan)

	ad := MakeHandlerDispatcher(outChan)
	t1 := &Test1Handler{
		Vals: make([]string, 0),
	}
	ad.RegisterHandler(t1)

	t2 := &Test2Handler{
		Vals: make([]string, 0),
	}
	ad.RegisterHandler(t2)

	rand.Seed(time.Now().UTC().UnixNano())
	// make test entries
	typestrs := []string{"http", "dns", "flow", "foo"}
	var createdEntries [10000]types.Entry
	entries := make(map[string]([]string))
	for i := 0; i < 10000; i++ {
		myIdentifier := fmt.Sprintf("val%d", i)
		myType := typestrs[rand.Intn(len(typestrs))]
		createdEntries[i] = types.Entry{
			EventType: myType,
			JSONLine:  myIdentifier,
		}
		if _, ok := entries[myType]; !ok {
			entries[myType] = make([]string, 0)
		}
		entries[myType] = append(entries[myType], myIdentifier)
		ad.Dispatch(&createdEntries[i])
	}

	close(outChan)
	<-closeChan

	if len(t1.Vals) != len(entries["dns"]) {
		t.Fatalf("wrong number of 'dns' entries delivered to DNS handler (%d/%d)",
			len(t1.Vals), len(entries["dns"]))
	}
	for i := 0; i < len(t1.Vals); i++ {
		if t1.Vals[i] != entries["dns"][i] {
			t.Fatalf("'dns' pair of entries differs: %s/%s", t1.Vals[i],
				entries["dns"][i])
		}
	}
	if len(t2.Vals) != len(entries["http"]) {
		t.Fatalf("wrong number of 'http' entries delivered to HTTP handler (%d/%d)",
			len(t2.Vals), len(entries["http"]))
	}
	for i := 0; i < len(t2.Vals); i++ {
		if t2.Vals[i] != entries["http"][i] {
			t.Fatalf("'http' pair of entries differs: %s/%s", t2.Vals[i],
				entries["http"][i])
		}
	}
}

func TestHandlerDispatcherMonitoring(t *testing.T) {
	serverURL := "amqp://sensor:sensor@127.0.0.1:9999/%2f/"

	// start mock AMQP server
	fakeServer := server.NewServer(serverURL)
	fakeServer.Start()
	defer fakeServer.Stop()

	// set up consumer
	results := make([]string, 0)
	c, err := util.NewConsumer(serverURL, "nsm.test.metrics", "direct", "nsm.test.metrics.testqueue",
		"", "", func(d wabbit.Delivery) {
			log.Info(string(d.Body()))
			results = append(results, string(d.Body()))
		})
	if err != nil {
		t.Fatal(err)
	}

	// set up submitter
	statssubmitter, err := util.MakeAMQPSubmitterWithReconnector(serverURL,
		"nsm.test.metrics", true, func(url string) (wabbit.Conn, string, error) {
			// we pass in a custom reconnector which uses the amqptest implementation
			var conn wabbit.Conn
			conn, err = amqptest.Dial(url)
			return conn, "direct", err
		})
	if err != nil {
		t.Fatal(err)
	}
	defer statssubmitter.Finish()

	// create InfluxDB line protocol encoder/submitter
	pse := util.MakePerformanceStatsEncoder(statssubmitter, 2*time.Second, false)

	outChan := make(chan types.Entry)
	closeChan := make(chan bool)
	ad := MakeHandlerDispatcher(outChan)
	ad.SubmitStats(pse)
	ad.Run()

	go func() {
		for i := 0; i < 100; i++ {
			ad.Dispatch(&types.Entry{
				JSONLine: "foo",
			})
			ad.Dispatch(&types.Entry{
				JSONLine: "bar",
			})
			ad.Dispatch(&types.Entry{
				JSONLine: "baz",
			})
			time.Sleep(50 * time.Millisecond)
		}
	}()

	go func(closeChan chan bool, inChan chan types.Entry) {
		i := 0
		for v := range inChan {
			_ = v
			i++
			if i == 300 {
				break
			}
		}
		close(closeChan)
	}(closeChan, outChan)

	<-closeChan
	close(outChan)

	stopChan := make(chan bool)
	ad.Stop(stopChan)
	<-stopChan

	c.Shutdown()

	if len(results) == 0 {
		t.Fatalf("unexpected result length: 0")
	}

	if match, _ := regexp.Match(fmt.Sprintf("^%s,[^ ]+ dispatch_calls_per_sec=[0-9]+", util.ToolName), []byte(results[0])); !match {
		t.Fatalf("unexpected match content: %s", results[0])
	}
}
