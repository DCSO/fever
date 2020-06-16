package processing

// DCSO FEVER
// Copyright (c) 2019, DCSO GmbH

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DCSO/fever/util"

	"github.com/NeowayLabs/wabbit"
	"github.com/NeowayLabs/wabbit/amqptest"
	"github.com/NeowayLabs/wabbit/amqptest/server"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

func TestContextShipperAMQP(t *testing.T) {
	serverURL := "amqp://sensor:sensor@localhost:9988/%2f/"
	log.SetLevel(log.DebugLevel)

	// start mock server
	fakeServer := server.NewServer(serverURL)
	fakeServer.Start()

	// set up consumer
	allDone := make(chan bool)
	coll := make([]string, 0)
	c, err := util.NewConsumer(serverURL, "context", "direct", "context",
		"context", "foo-test1", func(d wabbit.Delivery) {
			coll = append(coll, string(d.Body()))
			if len(coll) == 4 {
				allDone <- true
			}
		})
	if err != nil {
		t.Fatal(err)
	}

	// set up submitter
	submitter, err := util.MakeAMQPSubmitterWithReconnector(serverURL,
		"context", true, func(url string) (wabbit.Conn, error) {
			// we pass in a custom reconnector which uses the amqptest implementation
			var conn wabbit.Conn
			conn, err = amqptest.Dial(url)
			return conn, err
		})
	if err != nil {
		t.Fatal(err)
	}
	cs := &ContextShipperAMQP{}
	inChan, err := cs.Start(submitter)
	if err != nil {
		t.Fatal(err)
	}

	inChan <- Context{`{"value":"c1"}`}
	inChan <- Context{`{"value":"c2"}`}
	inChan <- Context{`{"value":"c3"}`}
	inChan <- Context{`{"value":"c4"}`}

	// ... and wait until they are received and processed
	<-allDone
	// check if output is correct
	if len(coll) != 4 {
		t.Fail()
	}
	if !strings.Contains(coll[0], `"value":"c1"`) {
		t.Fatalf("value 1 incorrect: %v", coll[0])
	}
	if !strings.Contains(coll[1], `"value":"c2"`) {
		t.Fatalf("value 2 incorrect: %v", coll[1])
	}
	if !strings.Contains(coll[2], `"value":"c3"`) {
		t.Fatalf("value 3 incorrect: %v", coll[2])
	}
	if !strings.Contains(coll[3], `"value":"c4"`) {
		t.Fatalf("value 4 incorrect: %v", coll[3])
	}

	close(inChan)

	// tear down test setup
	submitter.Finish()
	fakeServer.Stop()
	c.Shutdown()
}

func TestContextShipperAMQPBrokenJSON(t *testing.T) {
	cs := &ContextShipperAMQP{}
	ds, _ := util.MakeDummySubmitter()
	inChan, err := cs.Start(ds)
	if err != nil {
		t.Fatal(err)
	}

	hook := test.NewGlobal()
	var entries []*log.Entry

	inChan <- Context{`{""value":1}`}

	for i := 0; i < 60; i++ {
		time.Sleep(1 * time.Second)
		entries = hook.AllEntries()
		if len(entries) > 0 {
			break
		}
		if i > 58 {
			t.Fatalf("timed out trying to receive error message for malformed JSON")
		}
	}

	close(inChan)
	found := false

	for _, entry := range entries {
		if entry.Message == `could not marshal event JSON: {""value":1}` {
			found = true
			break
		}
	}

	if !found {
		var entryStrings bytes.Buffer
		for i, entry := range entries {
			entryStrings.WriteString(fmt.Sprintf("(%d: %s)", i, entry.Message))
		}
		t.Fatalf("malformed JSON error message not found: %v", entryStrings.String())
	}
}
