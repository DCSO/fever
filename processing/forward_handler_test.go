package processing

// DCSO FEVER
// Copyright (c) 2017, 2019, DCSO GmbH

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DCSO/fever/types"
	log "github.com/sirupsen/logrus"
)

func makeMultiForwarder(fn string, all bool, types []string) MultiForwardConfiguration {
	mf := MultiForwardConfiguration{
		Outputs: map[string]MultiForwardOutput{
			"default": MultiForwardOutput{
				Socket:       fn,
				All:          all,
				BufferLength: 100,
				Types:        types,
			},
		},
	}
	return mf
}

func makeEvent(eType string, tag string) types.Entry {
	e := types.Entry{
		SrcIP:     fmt.Sprintf("10.0.0.%d", rand.Intn(5)+1),
		SrcPort:   53,
		DestIP:    fmt.Sprintf("10.0.0.%d", rand.Intn(50)),
		DestPort:  []int64{11, 12, 13, 14, 15}[rand.Intn(5)],
		Timestamp: time.Now().Format(types.SuricataTimestampFormat),
		EventType: eType,
		Proto:     "TCP",
	}
	eve := types.EveEvent{
		EventType: e.EventType,
		SrcIP:     e.SrcIP,
		SrcPort:   int(e.SrcPort),
		DestIP:    e.DestIP,
		DestPort:  int(e.DestPort),
		Proto:     e.Proto,
		DNS: &types.DNSEvent{
			Rrname: tag,
		},
	}
	json, err := json.Marshal(eve)
	if err != nil {
		log.Warn(err)
	} else {
		e.JSONLine = string(json)
	}
	return e
}

func consumeSocket(inputListener net.Listener, stopChan chan bool,
	stoppedChan chan bool, t *testing.T, coll *[]string, wg *sync.WaitGroup) {
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
							wg.Done()
						}
					}
				}
			}
		}
	}
}

func TestForwardHandler(t *testing.T) {
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

	// prepare slice to hold collected strings
	coll := make([]string, 0)

	// setup comms channels
	clCh := make(chan bool)
	cldCh := make(chan bool)

	// start socket consumer
	var wg sync.WaitGroup
	wg.Add(2)
	go consumeSocket(inputListener, clCh, cldCh, t, &coll, &wg)

	// start forwarding handler
	c := make(chan types.Entry, 100)
	fh := MakeForwardHandler(c)
	mf := makeMultiForwarder(tmpfn, false, []string{"alert"})
	mf.Run(c, 5)

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

	// wait for socket consumer to receive all
	wg.Wait()

	if len(coll) != 2 {
		t.Fatalf("unexpected number of alerts: %d != 2", len(coll))
	}

	var eve types.EveOutEvent
	err = json.Unmarshal([]byte(coll[0]), &eve)
	if err != nil {
		t.Fatal(err)
	}
	if eve.DNS.Rrname != "foo1" {
		t.Fatalf("invalid event data, expected 'foo1', got %s", eve.DNS.Rrname)
	}
	err = json.Unmarshal([]byte(coll[1]), &eve)
	if err != nil {
		t.Fatal(err)
	}
	if eve.DNS.Rrname != "foo3" {
		t.Fatalf("invalid event data, expected 'foo3', got %s", eve.DNS.Rrname)
	}
}

func TestForwardHandlerWithAddedFields(t *testing.T) {
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

	// prepare slice to hold collected strings
	coll := make([]string, 0)

	// setup comms channels
	clCh := make(chan bool)
	cldCh := make(chan bool)

	// start socket consumer
	var wg sync.WaitGroup
	wg.Add(2)
	go consumeSocket(inputListener, clCh, cldCh, t, &coll, &wg)

	// start forwarding handler
	c := make(chan types.Entry)
	mf := makeMultiForwarder(tmpfn, false, []string{"alert"})
	fh := MakeForwardHandler(c)
	mf.Run(c, 5)
	fh.AddFields(map[string]string{
		"foo": "bar",
	})

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
	e = makeEvent("alert", "foo2")
	fh.Consume(&e)

	// wait for socket consumer to receive all
	wg.Wait()

	if len(coll) != 2 {
		t.Fatalf("unexpected number of alerts: %d != 2", len(coll))
	}

	var eve types.EveOutEvent
	err = json.Unmarshal([]byte(coll[0]), &eve)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(coll[0], `"foo":"bar"`) {
		t.Fatal("added string missing: ", coll[0])
	}
	err = json.Unmarshal([]byte(coll[1]), &eve)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(coll[1], `"foo":"bar"`) {
		t.Fatal("added string missing: ", coll[1])
	}
}

func TestForwardAllHandler(t *testing.T) {
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

	// prepare slice to hold collected strings
	coll := make([]string, 0)

	// setup comms channels
	clCh := make(chan bool)
	cldCh := make(chan bool)

	// start socket consumer
	var wg sync.WaitGroup
	wg.Add(3)
	go consumeSocket(inputListener, clCh, cldCh, t, &coll, &wg)

	// start forwarding handler
	c := make(chan types.Entry, 100)
	mf := makeMultiForwarder(tmpfn, true, []string{})
	fh := MakeForwardHandler(c)
	mf.Run(c, 5)

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

	wg.Wait()

	// stop socket consumer
	inputListener.Close()
	close(clCh)

	if len(coll) != 3 {
		t.Fatalf("unexpected number of alerts: %d != 3", len(coll))
	}
	var eve types.EveOutEvent
	err = json.Unmarshal([]byte(coll[0]), &eve)
	if err != nil {
		t.Fatal(err)
	}
	if eve.DNS.Rrname != "foo1" {
		t.Fatalf("invalid event data, expected 'foo1', got %s", eve.DNS.Rrname)
	}
	err = json.Unmarshal([]byte(coll[1]), &eve)
	if err != nil {
		t.Fatal(err)
	}
	if eve.DNS.Rrname != "foo2" {
		t.Fatalf("invalid event data, expected 'foo2', got %s", eve.DNS.Rrname)
	}
	err = json.Unmarshal([]byte(coll[2]), &eve)
	if err != nil {
		t.Fatal(err)
	}
	if eve.DNS.Rrname != "foo3" {
		t.Fatalf("invalid event data, expected 'foo3', got %s", eve.DNS.Rrname)
	}
}
