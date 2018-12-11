package processing

// DCSO FEVER
// Copyright (c) 2017, 2018, DCSO GmbH

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	"github.com/DCSO/bloom"
	log "github.com/sirupsen/logrus"
)

var (
	reHTTPURL  = regexp.MustCompile(`Possibly bad HTTP URL: [^ ]+ . ([^ ]+) . ([^" ]+)`)
	reHTTPHost = regexp.MustCompile(`Possibly bad HTTP host: ([^" ]+)`)
	reDNS      = regexp.MustCompile("Possibly bad DNS lookup to ([^\" ]+)")
	reSNI      = regexp.MustCompile("Possibly bad TLS SNI: ([^\" ]+)")
)

func makeBloomDNSEvent(rrname string) types.Entry {
	e := types.Entry{
		SrcIP:     fmt.Sprintf("10.0.0.%d", rand.Intn(5)+1),
		SrcPort:   53,
		DestIP:    fmt.Sprintf("10.0.0.%d", rand.Intn(50)),
		DestPort:  []int64{11, 12, 13, 14, 15}[rand.Intn(5)],
		Timestamp: time.Now().Format(types.SuricataTimestampFormat),
		EventType: "dns",
		Proto:     "TCP",
		DNSRCode:  []string{"NOERROR", "NXDOMAIN"}[rand.Intn(2)],
		DNSRData:  fmt.Sprintf("10.%d.0.%d", rand.Intn(50), rand.Intn(50)+100),
		DNSRRName: rrname,
		DNSRRType: "answer",
	}
	eve := types.EveEvent{
		EventType: e.EventType,
		SrcIP:     e.SrcIP,
		SrcPort:   int(e.SrcPort),
		DestIP:    e.DestIP,
		DestPort:  int(e.DestPort),
		Proto:     e.Proto,
		DNS: &types.DNSEvent{
			Rcode:  e.DNSRCode,
			Rrname: e.DNSRRName,
			Rdata:  e.DNSRData,
			Rrtype: e.DNSRRType,
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

func makeBloomHTTPEvent(host string, url string) types.Entry {
	e := types.Entry{
		SrcIP:      fmt.Sprintf("10.0.0.%d", rand.Intn(5)+1),
		SrcPort:    int64(rand.Intn(60000) + 1025),
		DestIP:     fmt.Sprintf("10.0.0.%d", rand.Intn(50)),
		DestPort:   80,
		Timestamp:  time.Now().Format(types.SuricataTimestampFormat),
		EventType:  "http",
		Proto:      "TCP",
		HTTPHost:   host,
		HTTPUrl:    url,
		HTTPMethod: "GET",
	}
	eve := types.EveEvent{
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

func makeBloomTLSEvent(host string) types.Entry {
	e := types.Entry{
		SrcIP:     fmt.Sprintf("10.0.0.%d", rand.Intn(5)+1),
		SrcPort:   int64(rand.Intn(60000) + 1025),
		DestIP:    fmt.Sprintf("10.0.0.%d", rand.Intn(50)),
		DestPort:  443,
		Timestamp: time.Now().Format(types.SuricataTimestampFormat),
		EventType: "tls",
		Proto:     "TCP",
		TLSSni:    host,
	}
	eve := types.EveEvent{
		EventType: e.EventType,
		SrcIP:     e.SrcIP,
		SrcPort:   int(e.SrcPort),
		DestIP:    e.DestIP,
		DestPort:  int(e.DestPort),
		Proto:     e.Proto,
		TLS: &types.TLSEvent{
			Sni: e.TLSSni,
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

var testURLs []string
var testHosts []string
var testTLSHosts []string

const numOfTestBloomItems = 1000

// fill Bloom filter with disjunct set of values
func fillBloom(b *bloom.BloomFilter) {
	testURLs = make([]string, 0)
	testHosts = make([]string, 0)
	testTLSHosts = make([]string, 0)
	i := 0
	for i < numOfTestBloomItems {
		val := fmt.Sprintf("%s.com", util.RandStringBytesMaskImprSrc(6))
		for b.Check([]byte(val)) {
			val = fmt.Sprintf("%s.com", util.RandStringBytesMaskImprSrc(6))
		}
		i++
		testHosts = append(testHosts, val)
		b.Add([]byte(val))
	}
	i = 0
	for i < numOfTestBloomItems {
		val := fmt.Sprintf("%s.com", util.RandStringBytesMaskImprSrc(6))
		for b.Check([]byte(val)) {
			val = fmt.Sprintf("%s.com", util.RandStringBytesMaskImprSrc(6))
		}
		i++
		testTLSHosts = append(testTLSHosts, val)
		b.Add([]byte(val))
	}
	i = 0
	for i < numOfTestBloomItems {
		val := fmt.Sprintf("http://foo.com/%s.html", util.RandStringBytesMaskImprSrc(6))
		for b.Check([]byte(val)) {
			val = fmt.Sprintf("http://foo.com/%s.html", util.RandStringBytesMaskImprSrc(6))
		}
		i++
		testURLs = append(testURLs, val)
		b.Add([]byte(val))
	}
}

// CollectorHandler simply gathers consumed events in a list
type CollectorHandler struct {
	Entries map[string]bool
}

func (h *CollectorHandler) GetName() string {
	return "Collector handler"
}

func (h *CollectorHandler) GetEventTypes() []string {
	return []string{"alert"}
}

func (h *CollectorHandler) Consume(e *types.Entry) error {
	match := reHTTPURL.FindStringSubmatch(e.JSONLine)
	if match != nil {
		url := match[2]
		h.Entries[url] = true
		return nil
	}
	match = reHTTPHost.FindStringSubmatch(e.JSONLine)
	if match != nil {
		host := match[1]
		h.Entries[host] = true
		return nil
	}
	match = reDNS.FindStringSubmatch(e.JSONLine)
	if match != nil {
		h.Entries[match[1]] = true
		return nil
	}
	match = reSNI.FindStringSubmatch(e.JSONLine)
	if match != nil {
		h.Entries[match[1]] = true
		return nil
	}
	return nil
}

func TestBloomHandler(t *testing.T) {
	// make sure that alers are forwarded
	util.PrepareEventFilter([]string{"alert"}, false)

	// initalize Bloom filter and fill with 'interesting' values
	bf := bloom.Initialize(100000, 0.0000001)
	fillBloom(&bf)

	// channel to receive events to be saved to database
	dbChan := make(chan types.Entry)

	// handler to receive forwarded events
	fwhandler := &CollectorHandler{
		Entries: make(map[string]bool),
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

	bh := MakeBloomHandler(&bf, dbChan, fwhandler, "FOO BAR")

	err := bh.Reload()
	if err == nil {
		t.Fatal("reloading without file should fail")
	}

	bhTypes := bh.GetEventTypes()
	if len(bhTypes) != 3 {
		t.Fatal("Bloom handler should claim three types")
	}
	if bhTypes[0] != "http" {
		t.Fatal("Bloom handler should claim 'http' type")
	}
	if bhTypes[1] != "dns" {
		t.Fatal("Bloom handler should claim 'dns' type")
	}
	if bhTypes[2] != "tls" {
		t.Fatal("Bloom handler should claim 'tls' type")
	}
	if bh.GetName() != "Bloom filter handler" {
		t.Fatal("Bloom handler has wrong name")
	}

	i := 0
	j := 0
	k := 0
	for {
		var e types.Entry
		// emit Bloom filter TP event with 20% individual probability, at most
		// <numOfTestBloomItems> each
		if 2 < rand.Intn(10) {
			if i == numOfTestBloomItems && j == numOfTestBloomItems && k == numOfTestBloomItems {
				break
			}
			// uniformly distribute hits over HTTP URL/Host and DNS lookups
			switch rnd := rand.Intn(3); rnd {
			case 0:
				if i < numOfTestBloomItems {
					e = makeBloomDNSEvent(testHosts[i])
					bh.Consume(&e)
					i++
				}
			case 1:
				if j < numOfTestBloomItems {
					e = makeBloomHTTPEvent("foo.com", testURLs[j])
					bh.Consume(&e)
					j++
				}
			case 2:
				if k < numOfTestBloomItems {
					e = makeBloomTLSEvent(testTLSHosts[k])
					bh.Consume(&e)
					k++
				}
			}
		} else {
			// uniformly distribute non-matching hits over HTTP URL/Host and DNS lookups
			switch rnd := rand.Intn(3); rnd {
			case 0:
				s := fmt.Sprintf("%s.com", util.RandStringBytesMaskImprSrc(6))
				for bf.Check([]byte(s)) {
					s = fmt.Sprintf("%s.%s", util.RandStringBytesMaskImprSrc(6),
						util.RandStringBytesMaskImprSrc(2))
				}
				e = makeBloomDNSEvent(s)
				bh.Consume(&e)
			case 1:
				s := fmt.Sprintf("/%s.html", util.RandStringBytesMaskImprSrc(6))
				for bf.Check([]byte(s)) {
					s = fmt.Sprintf("/%s.%s.html", util.RandStringBytesMaskImprSrc(6),
						util.RandStringBytesMaskImprSrc(6))
				}
				e = makeBloomHTTPEvent("foo.com", s)
				bh.Consume(&e)
			case 2:
				s := fmt.Sprintf("%s.com", util.RandStringBytesMaskImprSrc(6))
				for bf.Check([]byte(s)) {
					s = fmt.Sprintf("%s.%s", util.RandStringBytesMaskImprSrc(6),
						util.RandStringBytesMaskImprSrc(2))
				}
				e = makeBloomTLSEvent(s)
				bh.Consume(&e)
			}
		}
	}

	// wait until all values have been collected
	close(dbChan)
	<-consumeWaitChan

	// check that we haven't missed anything
	if len(fwhandler.Entries) < 3*numOfTestBloomItems {
		t.Fatalf("expected %d forwarded BLF alerts, seen less (%d)", numOfTestBloomItems,
			len(fwhandler.Entries))
	}

	// we want _at least_ to have the test values forwarded as alerts
	// (as FP are possible)
	for _, v := range testHosts {
		if _, ok := fwhandler.Entries[v]; !ok {
			t.Fatalf("testhost %s not forwarded", v)
		}
	}

	for _, v := range testURLs {
		if _, ok := fwhandler.Entries[v]; !ok {
			t.Fatalf("testurl %s not forwarded", v)
		}
	}
}

func TestBloomHandlerFromFile(t *testing.T) {
	b1 := bloom.Initialize(1000, 0.0001)
	b2 := bloom.Initialize(1000, 0.0001)

	b1.Add([]byte("foobar"))
	b2.Add([]byte("baz"))

	b1File, err := ioutil.TempFile("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(b1File.Name())
	b1.Write(b1File)
	b1File.Close()

	// handler to receive forwarded events
	fwhandler := &CollectorHandler{
		Entries: make(map[string]bool),
	}

	dbChan := make(chan types.Entry, 10)
	defer close(dbChan)

	bh, err := MakeBloomHandlerFromFile(b1File.Name(), false, dbChan, fwhandler, "FOO BAR")
	if err != nil {
		t.Fatal(err)
	}

	e := makeBloomDNSEvent("foobar")
	bh.Consume(&e)

	if len(fwhandler.Entries) != 1 {
		t.Fatalf("Unexpected number of entries: %d != 1 ", len(fwhandler.Entries))
	}
	if !fwhandler.Entries["foobar"] {
		t.Fatalf("expected entry is missing")
	}
	e = makeBloomDNSEvent("baz")
	bh.Consume(&e)
	if len(fwhandler.Entries) != 1 {
		t.Fatalf("Unexpected number of entries: %d != 1 ", len(fwhandler.Entries))
	}
	if !fwhandler.Entries["foobar"] {
		t.Fatalf("expected entry is missing")
	}

	b2File, err := os.OpenFile(b1File.Name(), os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		t.Fatal(err)
	}
	b2.Write(b2File)
	b2File.Close()

	bh.Reload()
	fwhandler.Entries = make(map[string]bool)

	e = makeBloomDNSEvent("baz")
	bh.Consume(&e)

	if len(fwhandler.Entries) != 1 {
		t.Fatalf("Unexpected number of entries: %d != 1 ", len(fwhandler.Entries))
	}
	if !fwhandler.Entries["baz"] {
		t.Fatalf("expected entry is missing")
	}
	if fwhandler.Entries["foobar"] {
		t.Fatalf("unexpected entry")
	}
	e = makeBloomDNSEvent("foobar")
	bh.Consume(&e)
	if len(fwhandler.Entries) != 1 {
		t.Fatalf("Unexpected number of entries: %d != 1 ", len(fwhandler.Entries))
	}
	if !fwhandler.Entries["baz"] {
		t.Fatalf("expected entry is missing")
	}
	if fwhandler.Entries["foobar"] {
		t.Fatalf("unexpected entry")
	}
}

func TestBloomHandlerEmptyInput(t *testing.T) {
	blFile, err := ioutil.TempFile("", "empty")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(blFile.Name())
	blFile.Close()

	dbChan := make(chan types.Entry, 10)
	defer close(dbChan)

	bf, err := MakeBloomHandlerFromFile(blFile.Name(), false, dbChan, nil, "FOO BAR")
	if err != nil {
		t.Fatal(err)
	}
	if bf == nil {
		t.Fatal("bloom filter should not be nil for empty file")
	}
}
