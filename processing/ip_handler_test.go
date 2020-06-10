package processing

// DCSO FEVER
// Copyright (c) 2018, 2020, DCSO GmbH

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/yl2chen/cidranger"
)

var (
	reIPmsg = regexp.MustCompile(`Communication involving IP ([^ ]+) in listed range ([^ ]+)`)
)

func makeIPHTTPEvent(srcip string, dstip string) types.Entry {
	e := types.Entry{
		SrcIP:      srcip,
		SrcPort:    int64(rand.Intn(60000) + 1025),
		DestIP:     dstip,
		DestPort:   80,
		Timestamp:  time.Now().Format(types.SuricataTimestampFormat),
		EventType:  "http",
		Proto:      "TCP",
		HTTPHost:   "http://foo.bar",
		HTTPUrl:    "/baz",
		HTTPMethod: "GET",
	}
	eve := types.EveEvent{
		Timestamp: &types.SuriTime{
			Time: time.Now().UTC(),
		},
		EventType: e.EventType,
		SrcIP:     e.SrcIP,
		SrcPort:   int(e.SrcPort),
		DestIP:    e.DestIP,
		DestPort:  int(e.DestPort),
		Proto:     e.Proto,
		HTTP: &types.HTTPEvent{
			Hostname: e.HTTPHost,
			URL:      e.HTTPUrl,
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

// IPCollectorHandler gathers consumed alerts in a list
type IPCollectorHandler struct {
	Entries []string
}

func (h *IPCollectorHandler) GetName() string {
	return "Collector handler"
}

func (h *IPCollectorHandler) GetEventTypes() []string {
	return []string{"alert"}
}

func (h *IPCollectorHandler) Consume(e *types.Entry) error {
	match := reIPmsg.FindStringSubmatch(e.JSONLine)
	if match != nil {
		h.Entries = append(h.Entries, e.JSONLine)
		return nil
	}
	return nil
}

func TestIPHandler(t *testing.T) {
	// make sure that alerts are forwarded
	util.PrepareEventFilter([]string{"alert"}, false)

	// channel to receive events to be saved to database
	dbChan := make(chan types.Entry)

	// handler to receive forwarded events
	fwhandler := &IPCollectorHandler{
		Entries: make([]string, 0),
	}

	// concurrently gather entries to be written to DB
	dbWritten := make([]types.Entry, 0)
	consumeWaitChan := make(chan bool)
	go func() {
		for e := range dbChan {
			dbWritten = append(dbWritten, e)
		}
		close(consumeWaitChan)
	}()

	// make test ranger
	_, network, _ := net.ParseCIDR("10.0.0.1/32")
	rng := cidranger.NewPCTrieRanger()
	rng.Insert(cidranger.NewBasicRangerEntry(*network))

	ih := MakeIPHandler(rng, dbChan, fwhandler, "IPF")

	bhTypes := ih.GetEventTypes()
	if len(bhTypes) != 8 {
		t.Fatal("IP handler should claim eight types")
	}
	if ih.GetName() != "IP blacklist handler" {
		t.Fatal("IP handler has wrong name")
	}

	e := makeIPHTTPEvent("10.0.0.1", "10.0.0.2")
	ih.Consume(&e)
	e = makeIPHTTPEvent("10.0.0.3", "10.0.0.2")
	ih.Consume(&e)
	e = makeIPHTTPEvent("10.0.0.3", "10.0.0.1")
	ih.Consume(&e)

	// wait until all values have been collected
	close(dbChan)
	<-consumeWaitChan

	// check that we haven't missed anything
	if len(fwhandler.Entries) < 2 {
		t.Fatalf("expected %d forwarded BLF alerts, seen less (%d)", 2,
			len(fwhandler.Entries))
	}

	// check that the result is indeed valid JSON again
	var result interface{}
	err := json.Unmarshal([]byte(fwhandler.Entries[0]), &result)
	if err != nil {
		t.Fatalf("could not unmarshal JSON: %s", err.Error())
	}
	err = json.Unmarshal([]byte(fwhandler.Entries[1]), &result)
	if err != nil {
		t.Fatalf("could not unmarshal JSON: %s", err.Error())
	}
}

func TestIPHandlerFromFile(t *testing.T) {
	// make sure that alerts are forwarded
	util.PrepareEventFilter([]string{"alert"}, false)

	// channel to receive events to be saved to database
	dbChan := make(chan types.Entry)

	// handler to receive forwarded events
	fwhandler := &IPCollectorHandler{
		Entries: make([]string, 0),
	}

	// concurrently gather entries to be written to DB
	dbWritten := make([]types.Entry, 0)
	consumeWaitChan := make(chan bool)
	go func() {
		for e := range dbChan {
			dbWritten = append(dbWritten, e)
		}
		close(consumeWaitChan)
	}()

	ipFile, err := ioutil.TempFile("", "ipexample")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(ipFile.Name())
	w := bufio.NewWriter(ipFile)
	_, err = w.WriteString("10.0.0.1/32\n")
	if err != nil {
		t.Fatal(err)
	}
	w.Flush()
	ipFile.Close()

	ih, err := MakeIPHandlerFromFile(ipFile.Name(), dbChan, fwhandler, "IPF")
	if err != nil {
		t.Fatal(err)
	}

	bhTypes := ih.GetEventTypes()
	if len(bhTypes) != 8 {
		t.Fatal("IP handler should claim eight types")
	}
	if ih.GetName() != "IP blacklist handler" {
		t.Fatal("IP handler has wrong name")
	}

	e := makeIPHTTPEvent("10.0.0.1", "10.0.0.2")
	ih.Consume(&e)
	e = makeIPHTTPEvent("10.0.0.3", "10.0.0.2")
	ih.Consume(&e)
	e = makeIPHTTPEvent("10.0.0.3", "10.0.0.1")
	ih.Consume(&e)

	// wait until all values have been collected
	close(dbChan)
	<-consumeWaitChan

	// check that we haven't missed anything
	if len(fwhandler.Entries) < 2 {
		t.Fatalf("expected %d forwarded BLF alerts, seen less (%d)", 2,
			len(fwhandler.Entries))
	}

	var i interface{}
	err = json.Unmarshal([]byte(fwhandler.Entries[0]), &i)
	if err != nil {
		t.Fatalf("could not unmarshal JSON: %s", err.Error())
	}
	err = json.Unmarshal([]byte(fwhandler.Entries[1]), &i)
	if err != nil {
		t.Fatalf("could not unmarshal JSON: %s", err.Error())
	}
}

func TestIPHandlerFromFileInvalidFormat(t *testing.T) {
	// channel to receive events to be saved to database
	dbChan := make(chan types.Entry)

	// handler to receive forwarded events
	fwhandler := &IPCollectorHandler{
		Entries: make([]string, 0),
	}

	ipFile, err := ioutil.TempFile("", "invalidipexample")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(ipFile.Name())
	w := bufio.NewWriter(ipFile)
	_, err = w.WriteString("10.0.0.1/3q5435\n")
	if err != nil {
		t.Fatal(err)
	}
	w.Flush()
	ipFile.Close()

	hook := test.NewGlobal()
	_, err = MakeIPHandlerFromFile(ipFile.Name(), dbChan, fwhandler, "IPF")
	if err != nil {
		t.Fatal(err)
	}

	entries := hook.AllEntries()
	if len(entries) < 2 {
		t.Fatal("missing log entries")
	}
	if entries[0].Message != "invalid IP range 10.0.0.1/3q5435, skipping" {
		t.Fatal("wrong log entry for invalid IP range")
	}
}
