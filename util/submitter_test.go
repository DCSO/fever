package util

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"bytes"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/NeowayLabs/wabbit"
	"github.com/NeowayLabs/wabbit/amqptest"
	"github.com/NeowayLabs/wabbit/amqptest/server"
)

func TestSubmitter(t *testing.T) {
	serverURL := "amqp://sensor:sensor@localhost:9999/%2f/"
	log.SetLevel(log.DebugLevel)

	// start mock server
	fakeServer := server.NewServer(serverURL)
	fakeServer.Start()

	// set up consumer
	var buf bytes.Buffer
	allDone := make(chan bool)
	c, err := NewConsumer(serverURL, "foo.bar.test", "direct", "foo",
		"foo", "foo-test1", func(d wabbit.Delivery) {
			buf.Write(d.Body())
			if buf.Len() == 4 {
				allDone <- true
			}
		})
	if err != nil {
		t.Fatal(err)
	}

	// set up submitter
	submitter, err := MakeAMQPSubmitterWithReconnector(serverURL,
		"foo.bar.test", true, func(url string) (wabbit.Conn, error) {
			// we pass in a custom reconnector which uses the amqptest implementation
			var conn wabbit.Conn
			conn, err = amqptest.Dial(url)
			return conn, err
		})
	if err != nil {
		t.Fatal(err)
	}

	// send some messages...
	submitter.Submit([]byte("1"), "foo", "text/plain")
	submitter.Submit([]byte("2"), "foo", "text/plain")
	submitter.Submit([]byte("3"), "foo", "text/plain")
	submitter.Submit([]byte("4"), "foo", "text/plain")

	// ... and wait until they are received and processed
	<-allDone
	// check if order and length is correct
	if buf.String() != "1234" {
		t.Fail()
	}

	// tear down test setup
	submitter.Finish()
	fakeServer.Stop()
	c.Shutdown()

}

func TestSubmitterReconnect(t *testing.T) {
	serverURL := "amqp://sensor:sensor@localhost:9992/%2f/"
	log.SetLevel(log.DebugLevel)

	// start mock server
	fakeServer := server.NewServer(serverURL)
	fakeServer.Start()

	// set up consumer
	var buf bytes.Buffer
	done := make(chan bool)
	c, err := NewConsumer(serverURL, "foo.bar.test", "direct", "foo",
		"foo", "foo-test1", func(d wabbit.Delivery) {
			buf.Write(d.Body())
			log.Printf("received '%s', buf length %d", d.Body(), buf.Len())
			if buf.Len() == 2 {
				done <- true
			}
		})
	if err != nil {
		t.Fatal(err)
	}

	// set up submitter
	submitter, err := MakeAMQPSubmitterWithReconnector(serverURL,
		"foo.bar.test", true, func(url string) (wabbit.Conn, error) {
			// we pass in a custom reconnector which uses the amqptest implementation
			var conn wabbit.Conn
			conn, err = amqptest.Dial(url)
			return conn, err
		})
	if err != nil {
		t.Fatal(err)
	}
	defer submitter.Finish()

	// send some messages...
	submitter.Submit([]byte("A"), "foo", "text/plain")
	submitter.Submit([]byte("B"), "foo", "text/plain")
	stopped := make(chan bool)
	restarted := make(chan bool)
	<-done
	go func() {
		fakeServer.Stop()
		close(stopped)
		time.Sleep(5 * time.Second)
		fakeServer := server.NewServer(serverURL)
		fakeServer.Start()
		close(restarted)
	}()
	<-stopped
	log.Info("server stopped")

	// these are buffered on client side because submitter will not publish
	// with immediate flag set
	submitter.Submit([]byte("C"), "foo", "text/plain")
	submitter.Submit([]byte("D"), "foo", "text/plain")

	<-restarted
	log.Info("server restarted")

	// reconnect consumer
	c.Shutdown()
	c2, err := NewConsumer(serverURL, "foo.bar.test", "direct", "foo",
		"foo", "foo-test1", func(d wabbit.Delivery) {
			buf.Write(d.Body())
			log.Printf("received '%s', buf length %d", d.Body(), buf.Len())
			if buf.Len() == 6 {
				done <- true
			}
		})
	if err != nil {
		t.Fatal(err)
	}

	submitter.Submit([]byte("E"), "foo", "text/plain")
	submitter.Submit([]byte("F"), "foo", "text/plain")

	// ... and wait until they are received and processed
	<-done
	log.Debug("All done")

	// check if order and length is correct
	log.Info(buf.String())
	if buf.String() != "ABCDEF" {
		t.Fail()
	}

	// tear down test setup
	c2.Shutdown()
	fakeServer.Stop()
}
