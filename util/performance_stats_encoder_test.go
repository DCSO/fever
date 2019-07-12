package util

// DCSO FEVER
// Copyright (c) 2017, 2019, DCSO GmbH

import (
	"fmt"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/NeowayLabs/wabbit"
	"github.com/NeowayLabs/wabbit/amqptest"
	"github.com/NeowayLabs/wabbit/amqptest/server"
	log "github.com/sirupsen/logrus"
)

var testStruct = struct {
	TestVal  uint64 `influx:"testval"`
	TestVal2 uint64 `influx:"testvalue"`
	TestVal3 uint64
}{
	1,
	2,
	3,
}

var testStructUntagged = struct {
	TestVal  uint64
	TestVal2 uint64
	TestVal3 uint64
}{
	1,
	2,
	3,
}

func TestPerformanceStatsEncoderEmpty(t *testing.T) {
	serverURL := "amqp://sensor:sensor@127.0.0.1:9999/%2f/"

	// start mock AMQP server
	fakeServer := server.NewServer(serverURL)
	fakeServer.Start()
	defer fakeServer.Stop()

	// set up consumer
	results := make([]string, 0)
	c, err := NewConsumer(serverURL, "tdh.metrics", "direct", "tdh.metrics.testqueue",
		"", "", func(d wabbit.Delivery) {
			results = append(results, string(d.Body()))
		})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Shutdown()

	// set up submitter
	statssubmitter, err := MakeAMQPSubmitterWithReconnector(serverURL,
		"tdh.metrics", true, func(url string) (wabbit.Conn, error) {
			// we pass in a custom reconnector which uses the amqptest implementation
			var conn wabbit.Conn
			conn, err = amqptest.Dial(url)
			return conn, err
		})
	if err != nil {
		t.Fatal(err)
	}
	defer statssubmitter.Finish()

	// create InfluxDB line protocol encoder/submitter
	pse := MakePerformanceStatsEncoder(statssubmitter, 1*time.Second, false)
	pse.Submit(testStructUntagged)
	time.Sleep(1 * time.Second)

	if len(results) != 0 {
		t.Fatalf("unexpected result length: %d !=0", len(results))
	}
}

func TestPerformanceStatsEncoder(t *testing.T) {
	serverURL := "amqp://sensor:sensor@127.0.0.1:9999/%2f/"

	// start mock AMQP server
	fakeServer := server.NewServer(serverURL)
	fakeServer.Start()
	defer fakeServer.Stop()

	// set up consumer
	results := make([]string, 0)
	gateChan := make(chan bool)
	var resultsLock sync.Mutex
	c, err := NewConsumer(serverURL, "tdh.metrics", "direct", "tdh.metrics.testqueue",
		"", "", func(d wabbit.Delivery) {
			resultsLock.Lock()
			results = append(results, string(d.Body()))
			resultsLock.Unlock()
			log.Info(string(d.Body()))
			gateChan <- true
		})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Shutdown()

	// set up submitter
	statssubmitter, err := MakeAMQPSubmitterWithReconnector(serverURL,
		"tdh.metrics", true, func(url string) (wabbit.Conn, error) {
			// we pass in a custom reconnector which uses the amqptest implementation
			var conn wabbit.Conn
			conn, err = amqptest.Dial(url)
			return conn, err
		})
	if err != nil {
		t.Fatal(err)
	}
	defer statssubmitter.Finish()

	// create InfluxDB line protocol encoder/submitter
	pse := MakePerformanceStatsEncoder(statssubmitter, 1*time.Second, false)
	pse.Submit(testStruct)
	<-gateChan
	pse.Submit(testStruct)
	<-gateChan
	testStruct.TestVal = 3
	pse.Submit(testStruct)
	<-gateChan
	pse.Submit(testStruct)
	<-gateChan

	resultsLock.Lock()
	if len(results) != 4 {
		t.Fatalf("unexpected result length: %d != 4", len(results))
	}
	if match, _ := regexp.Match(fmt.Sprintf("^%s,[^ ]+ testval=1,testvalue=2", ToolName), []byte(results[0])); !match {
		t.Fatalf("unexpected match content: %s", results[0])
	}
	if match, _ := regexp.Match(fmt.Sprintf("^%s,[^ ]+ testval=1,testvalue=2", ToolName), []byte(results[1])); !match {
		t.Fatalf("unexpected match content: %s", results[1])
	}
	if match, _ := regexp.Match(fmt.Sprintf("^%s,[^ ]+ testval=3,testvalue=2", ToolName), []byte(results[2])); !match {
		t.Fatalf("unexpected match content: %s", results[2])
	}
	if match, _ := regexp.Match(fmt.Sprintf("^%s,[^ ]+ testval=3,testvalue=2", ToolName), []byte(results[3])); !match {
		t.Fatalf("unexpected match content: %s", results[3])
	}
	resultsLock.Unlock()
}
