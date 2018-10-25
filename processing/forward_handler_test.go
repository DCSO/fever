package processing

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"
)

func makeEvent(eType string, jsonLine string) types.Entry {
	e := types.Entry{
		SrcIP:     fmt.Sprintf("10.0.0.%d", rand.Intn(5)+1),
		SrcPort:   53,
		DestIP:    fmt.Sprintf("10.0.0.%d", rand.Intn(50)),
		DestPort:  []int64{11, 12, 13, 14, 15}[rand.Intn(5)],
		Timestamp: time.Now().Format(types.SuricataTimestampFormat),
		EventType: eType,
		Proto:     "TCP",
		JSONLine:  jsonLine,
	}
	return e
}

func consumeSocket(inputListener net.Listener, stopChan chan bool,
	stoppedChan chan bool, t *testing.T, coll *[]string) {
	for {
		select {
		case <-stopChan:
			close(stoppedChan)
			return
		default:
			var conn net.Conn
			inputListener.(*net.UnixListener).SetDeadline(time.Now().Add(1e9))
			conn, err := inputListener.Accept()
			if nil != err {
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					continue
				}
				t.Log(err)
			}
			reader := bufio.NewReaderSize(conn, 10485760)
			for {
				select {
				case <-stopChan:
					inputListener.Close()
					close(stoppedChan)
					return
				default:
					line, isPrefix, rerr := reader.ReadLine()
					if rerr == nil || rerr != io.EOF {
						if isPrefix {
							t.Log("incomplete line read from input")
							continue
						} else {
							*coll = append(*coll, string(line))
						}
					}
				}
			}
		}
	}
}

func TestForwardHandler(t *testing.T) {
	util.PrepareEventFilter([]string{"alert"}, false)

	dir, err := ioutil.TempDir("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tmpfn := filepath.Join(dir, fmt.Sprintf("t%d", rand.Int63()))

	inputListener, err := net.Listen("unix", tmpfn)
	if err != nil {
		t.Fatal("error opening input socket:", err)
	}
	defer inputListener.Close()

	// start forwarding handler
	fh := MakeForwardHandler(5, tmpfn)
	fh.Run()

	// prepare slice to hold collected strings
	coll := make([]string, 0)

	// setup comms channels
	clCh := make(chan bool)
	cldCh := make(chan bool)

	// start socket consumer
	go consumeSocket(inputListener, clCh, cldCh, t, &coll)

	fhTypes := fh.GetEventTypes()
	if len(fhTypes) != 1 {
		t.Fatal("Forwarding handler should only claim one type")
	}
	if fhTypes[0] != "alert" {
		t.Fatal("Forwarding handler should claim 'alert' type")
	}
	if fh.GetName() != "Forwarding handler" {
		t.Fatal("Forwarding handler has wrong name")
	}

	e := makeEvent("alert", "foo1")
	fh.Consume(&e)
	e = makeEvent("http", "foo2")
	fh.Consume(&e)
	e = makeEvent("alert", "foo3")
	fh.Consume(&e)

	time.Sleep(5 * time.Second)

	// stop forwarding handler
	scChan := make(chan bool)
	fh.Stop(scChan)
	<-scChan

	// stop socket consumer
	inputListener.Close()
	close(clCh)
	<-cldCh

	if len(coll) != 2 {
		t.Fatal("unexpected number of alerts")
	}
	if coll[0] != "foo1" {
		t.Fatalf("invalid payload, expected 'foo1', got %s", coll[0])
	}
	if coll[1] != "foo3" {
		t.Fatalf("invalid payload, expected 'foo3', got %s", coll[1])
	}
}

func TestForwardAllHandler(t *testing.T) {
	util.PrepareEventFilter([]string{}, true)

	dir, err := ioutil.TempDir("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tmpfn := filepath.Join(dir, fmt.Sprintf("t%d", rand.Int63()))

	inputListener, err := net.Listen("unix", tmpfn)
	if err != nil {
		t.Fatal("error opening input socket:", err)
	}
	defer inputListener.Close()

	// start forwarding handler
	fh := MakeForwardHandler(5, tmpfn)
	fh.Run()

	// prepare slice to hold collected strings
	coll := make([]string, 0)

	// setup comms channels
	clCh := make(chan bool)
	cldCh := make(chan bool)

	// start socket consumer
	go consumeSocket(inputListener, clCh, cldCh, t, &coll)

	fhTypes := fh.GetEventTypes()
	if len(fhTypes) != 1 {
		t.Fatal("Forwarding handler should only claim one type")
	}
	if fhTypes[0] != "*" {
		t.Fatal("Forwarding handler should claim '*' type")
	}
	if fh.GetName() != "Forwarding handler" {
		t.Fatal("Forwarding handler has wrong name")
	}

	e := makeEvent("alert", "foo1")
	fh.Consume(&e)
	e = makeEvent("http", "foo2")
	fh.Consume(&e)
	e = makeEvent("alert", "foo3")
	fh.Consume(&e)

	time.Sleep(5 * time.Second)

	// stop forwarding handler
	scChan := make(chan bool)
	fh.Stop(scChan)
	<-scChan

	// stop socket consumer
	inputListener.Close()
	close(clCh)
	<-cldCh

	if len(coll) != 3 {
		t.Fatal("unexpected number of alerts")
	}
	if coll[0] != "foo1" {
		t.Fatalf("invalid payload, expected 'foo1', got %s", coll[0])
	}
	if coll[1] != "foo2" {
		t.Fatalf("invalid payload, expected 'foo2', got %s", coll[1])
	}
	if coll[2] != "foo3" {
		t.Fatalf("invalid payload, expected 'foo3', got %s", coll[2])
	}
}
