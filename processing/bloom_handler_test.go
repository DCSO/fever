package processing

// DCSO FEVER
// Copyright (c) 2017, 2020, DCSO GmbH

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	"github.com/DCSO/bloom"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

var (
	reHTTPURL     = regexp.MustCompile(`Possibly bad HTTP URL: [^ ]+ . ([^ ]+) . ([^" ]+)`)
	reHTTPHost    = regexp.MustCompile(`Possibly bad HTTP host: ([^" ]+)`)
	reDNSReq      = regexp.MustCompile("Possibly bad DNS lookup to ([^\" ]+)")
	reDNSRep      = regexp.MustCompile("Possibly bad DNS response for ([^\" ]+)")
	reSNI         = regexp.MustCompile("Possibly bad TLS SNI: ([^\" ]+)")
	reFingerprint = regexp.MustCompile("Possibly bad TLS Fingerprint: ([^\" ]+)")
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
		DNSRRType: "A",
		DNSType:   []string{"answer", "query"}[rand.Intn(2)],
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
		DNS: &types.DNSEvent{
			Rcode:  e.DNSRCode,
			Rrname: e.DNSRRName,
			Rdata:  e.DNSRData,
			Rrtype: e.DNSRRType,
			Type:   e.DNSType,
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

func makeBloomTLSEvent(host string, fingerprint string) types.Entry {
	e := types.Entry{
		SrcIP:          fmt.Sprintf("10.0.0.%d", rand.Intn(5)+1),
		SrcPort:        int64(rand.Intn(60000) + 1025),
		DestIP:         fmt.Sprintf("10.0.0.%d", rand.Intn(50)),
		DestPort:       443,
		Timestamp:      time.Now().Format(types.SuricataTimestampFormat),
		EventType:      "tls",
		Proto:          "TCP",
		TLSSNI:         host,
		TLSFingerprint: fingerprint,
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
		TLS: &types.TLSEvent{
			Sni:         e.TLSSNI,
			Fingerprint: e.TLSFingerprint,
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
var testTLSFingerprints []string

const numOfTestBloomItems = 1000

// fill Bloom filter with disjunct set of values
func fillBloom(b *bloom.BloomFilter) {
	testURLs = make([]string, 0)
	testHosts = make([]string, 0)
	testTLSHosts = make([]string, 0)
	i := 0
	for i < numOfTestBloomItems {
		val := fmt.Sprintf("%s.com", util.RndStringFromAlpha(6))
		for b.Check([]byte(val)) {
			val = fmt.Sprintf("%s.com", util.RndStringFromAlpha(6))
		}
		i++
		testHosts = append(testHosts, val)
		b.Add([]byte(val))
	}
	i = 0
	for i < numOfTestBloomItems {
		val := fmt.Sprintf("%s.com", util.RndStringFromAlpha(6))
		for b.Check([]byte(val)) {
			val = fmt.Sprintf("%s.com", util.RndStringFromAlpha(6))
		}
		i++
		testTLSHosts = append(testTLSHosts, val)
		b.Add([]byte(val))
	}
	i = 0
	for i < numOfTestBloomItems {
		val := fmt.Sprintf("http://foo.com/%s.html", util.RndStringFromAlpha(6))
		for b.Check([]byte(val)) {
			val = fmt.Sprintf("http://foo.com/%s.html", util.RndStringFromAlpha(6))
		}
		i++
		testURLs = append(testURLs, val)
		b.Add([]byte(val))
	}
	i = 0
	for i < numOfTestBloomItems {
		i++
		fingp := util.RndTLSFingerprint()
		testTLSFingerprints = append(testTLSFingerprints, fingp)
		b.Add([]byte(fingp))
	}
}

// CollectorHandler simply gathers consumed events in a list
type CollectorHandler struct {
	EntriesLock sync.Mutex
	Entries     map[string]bool
}

func (h *CollectorHandler) GetName() string {
	return "Collector handler"
}

func (h *CollectorHandler) GetEventTypes() []string {
	return []string{"alert"}
}

func (h *CollectorHandler) Consume(e *types.Entry) error {
	h.EntriesLock.Lock()
	defer h.EntriesLock.Unlock()
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
	match = reDNSReq.FindStringSubmatch(e.JSONLine)
	if match != nil {
		var eve types.EveEvent
		var err = json.Unmarshal([]byte(e.JSONLine), &eve)
		if err != nil {
			log.Fatal(err)
		}
		if eve.DNS.Type != "query" {
			log.Fatalf("request alert for type (%s) != query", eve.DNS.Type)
		}
		h.Entries[match[1]] = true
		return nil
	}
	match = reDNSRep.FindStringSubmatch(e.JSONLine)
	if match != nil {
		var eve types.EveEvent
		var err = json.Unmarshal([]byte(e.JSONLine), &eve)
		if err != nil {
			log.Fatal(err)
		}
		if eve.DNS.Type != "answer" {
			log.Fatalf("request alert for type (%s) != answer", eve.DNS.Type)
		}
		h.Entries[match[1]] = true
		return nil
	}
	match = reSNI.FindStringSubmatch(e.JSONLine)
	if match != nil {
		h.Entries[match[1]] = true
		return nil
	}
	match = reFingerprint.FindStringSubmatch(e.JSONLine)
	if match != nil {
		h.Entries[match[1]] = true
		return nil
	}
	return nil
}

func (h *CollectorHandler) Reset() {
	h.EntriesLock.Lock()
	defer h.EntriesLock.Unlock()
	h.Entries = make(map[string]bool)
}

func (h *CollectorHandler) GetEntries() map[string]bool {
	h.EntriesLock.Lock()
	defer h.EntriesLock.Unlock()
	return h.Entries
}

func TestBloomHandler(t *testing.T) {
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
	l := 0
	for {
		var e types.Entry
		// emit Bloom filter TP event with 20% individual probability, at most
		// <numOfTestBloomItems> each
		if 2 < rand.Intn(10) {
			if i == numOfTestBloomItems && j == numOfTestBloomItems && k == numOfTestBloomItems && l == numOfTestBloomItems {
				break
			}
			// uniformly distribute hits over HTTP URL/Host and DNS lookups
			switch rnd := rand.Intn(4); rnd {
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
					e = makeBloomTLSEvent(testTLSHosts[k], ":::")
					bh.Consume(&e)
					k++
				}
			case 3:
				if l < numOfTestBloomItems {
					e = makeBloomTLSEvent("foo.com", testTLSFingerprints[l])
					bh.Consume(&e)
					l++
				}
			}
		} else {
			// uniformly distribute non-matching hits over HTTP URL/Host and DNS lookups
			switch rnd := rand.Intn(4); rnd {
			case 0:
				s := fmt.Sprintf("%s.com", util.RndStringFromAlpha(6))
				for bf.Check([]byte(s)) {
					s = fmt.Sprintf("%s.%s", util.RndStringFromAlpha(6),
						util.RndStringFromAlpha(2))
				}
				e = makeBloomDNSEvent(s)
				bh.Consume(&e)
			case 1:
				s := fmt.Sprintf("/%s.html", util.RndStringFromAlpha(6))
				for bf.Check([]byte(s)) {
					s = fmt.Sprintf("/%s.%s.html", util.RndStringFromAlpha(6),
						util.RndStringFromAlpha(6))
				}
				e = makeBloomHTTPEvent("foo.com", s)
				bh.Consume(&e)
			case 2:
				s := fmt.Sprintf("%s.com", util.RndStringFromAlpha(6))
				for bf.Check([]byte(s)) {
					s = fmt.Sprintf("%s.%s", util.RndStringFromAlpha(6),
						util.RndStringFromAlpha(2))
				}
				e = makeBloomTLSEvent(s, ":::")
				bh.Consume(&e)
			case 3:
				f := util.RndStringFromAlpha(6)
				for bf.Check([]byte(f)) {
					f = util.RndStringFromAlpha(6)
				}
				e = makeBloomTLSEvent("foo.com", f)
				bh.Consume(&e)
			}
		}
	}

	// wait until all values have been collected
	close(dbChan)
	<-consumeWaitChan

	// check that we haven't missed anything
	if len(fwhandler.Entries) < 4*numOfTestBloomItems {
		t.Fatalf("expected %d forwarded BLF alerts, seen less (%d)", 4*numOfTestBloomItems,
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

	bh, err := MakeBloomHandlerFromFile(b1File.Name(), false, dbChan, fwhandler, "FOO BAR", []string{"/"})
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

	bf, err := MakeBloomHandlerFromFile(blFile.Name(), false, dbChan, nil, "FOO BAR", []string{"/"})
	if err != nil {
		t.Fatal(err)
	}
	if bf == nil {
		t.Fatal("bloom filter should not be nil for empty file")
	}
}

func TestBloomHandlerBlacklistedInputFromFile(t *testing.T) {
	b1 := bloom.Initialize(1000, 0.0001)
	b1.Add([]byte("/"))
	b1File, err := ioutil.TempFile("", "blist")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(b1File.Name())
	b1.Write(b1File)
	b1File.Close()

	b2 := bloom.Initialize(1000, 0.0001)
	b2.Add([]byte("/foobarbaz"))

	dbChan := make(chan types.Entry, 10)
	defer close(dbChan)

	hook := test.NewGlobal()
	_, err = MakeBloomHandlerFromFile(b1File.Name(), false, nil, nil, "FOO BAR", []string{"/"})
	if err != nil {
		t.Fatal(err)
	}
	entries := hook.AllEntries()
	if len(entries) != 4 {
		t.Fatal("missing log entries")
	}
	if entries[2].Message != "filter contains blacklisted indicator '/'" {
		t.Fatal("wrong log entry for invalid IP range")
	}

	b2File, err := os.OpenFile(b1File.Name(), os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		t.Fatal(err)
	}
	b2.Write(b2File)
	b2File.Close()

	bf, err := MakeBloomHandlerFromFile(b1File.Name(), false, nil, nil, "FOO BAR", []string{"/"})
	if err != nil {
		t.Fatal(err)
	}

	b2File, err = os.OpenFile(b1File.Name(), os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		t.Fatal(err)
	}
	b1.Write(b2File)
	b2File.Close()

	hook.Reset()
	err = bf.Reload()
	if err != nil {
		t.Fatal(err)
	}
	entries = hook.AllEntries()
	if len(entries) != 2 {
		t.Fatal("missing log entries")
	}
	if entries[0].Message != "filter contains blacklisted indicator '/'" {
		t.Fatal("wrong log entry for invalid IP range")
	}
}

func TestBloomHandlerURL(t *testing.T) {
	e1 := types.Entry{
		SrcIP:      "10.0.0.1",
		SrcPort:    23545,
		DestIP:     "10.0.0.2",
		DestPort:   80,
		Timestamp:  time.Now().Format(types.SuricataTimestampFormat),
		EventType:  "http",
		Proto:      "TCP",
		HTTPHost:   "foo.bar.de",
		HTTPUrl:    "http://foo.bar.de/oddlyspecific",
		HTTPMethod: "GET",
	}
	eve1 := types.EveEvent{
		EventType: e1.EventType,
		SrcIP:     e1.SrcIP,
		SrcPort:   int(e1.SrcPort),
		DestIP:    e1.DestIP,
		DestPort:  int(e1.DestPort),
		Proto:     e1.Proto,
		HTTP: &types.HTTPEvent{
			Hostname: e1.HTTPHost,
			URL:      e1.HTTPUrl,
		},
	}
	json1, err := json.Marshal(eve1)
	if err != nil {
		log.Warn(err)
	} else {
		e1.JSONLine = string(json1)
	}
	e2 := types.Entry{
		SrcIP:      "10.0.0.1",
		SrcPort:    23545,
		DestIP:     "10.0.0.2",
		DestPort:   80,
		Timestamp:  time.Now().Format(types.SuricataTimestampFormat),
		EventType:  "http",
		Proto:      "TCP",
		HTTPHost:   "foo.bar.de",
		HTTPUrl:    "/oddlyspecific",
		HTTPMethod: "GET",
	}
	eve2 := types.EveEvent{
		EventType: e2.EventType,
		SrcIP:     e2.SrcIP,
		SrcPort:   int(e2.SrcPort),
		DestIP:    e2.DestIP,
		DestPort:  int(e2.DestPort),
		Proto:     e2.Proto,
		HTTP: &types.HTTPEvent{
			Hostname: e2.HTTPHost,
			URL:      e2.HTTPUrl,
		},
	}
	json2, err := json.Marshal(eve2)
	if err != nil {
		log.Warn(err)
	} else {
		e2.JSONLine = string(json2)
	}
	e3 := types.Entry{
		SrcIP:      "10.0.0.1",
		SrcPort:    23545,
		DestIP:     "10.0.0.2",
		DestPort:   80,
		Timestamp:  time.Now().Format(types.SuricataTimestampFormat),
		EventType:  "http",
		Proto:      "TCP",
		HTTPHost:   "foo.bar.com",
		HTTPUrl:    "/oddlyspecific",
		HTTPMethod: "GET",
	}
	eve3 := types.EveEvent{
		EventType: e3.EventType,
		SrcIP:     e3.SrcIP,
		SrcPort:   int(e3.SrcPort),
		DestIP:    e3.DestIP,
		DestPort:  int(e3.DestPort),
		Proto:     e3.Proto,
		HTTP: &types.HTTPEvent{
			Hostname: e3.HTTPHost,
			URL:      e3.HTTPUrl,
		},
	}
	json3, err := json.Marshal(eve3)
	if err != nil {
		log.Warn(err)
	} else {
		e3.JSONLine = string(json3)
	}

	dbChan := make(chan types.Entry)
	dbWritten := make([]types.Entry, 0)
	consumeWaitChan := make(chan bool)
	go func() {
		for e := range dbChan {
			dbWritten = append(dbWritten, e)
		}
		close(consumeWaitChan)
	}()

	// initalize Bloom filter and fill with 'interesting' values
	bf := bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("/oddlyspecific"))

	// handler to receive forwarded events
	fwhandler := &CollectorHandler{
		Entries: make(map[string]bool),
	}

	bh := MakeBloomHandler(&bf, dbChan, fwhandler, "FOO BAR")
	bh.Consume(&e1)

	if len(fwhandler.GetEntries()) != 1 {
		t.Fatalf("not enough alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("foo.bar.de/oddlyspecific"))
	fwhandler.Reset()
	bh.Consume(&e1)

	if len(fwhandler.GetEntries()) != 1 {
		t.Fatalf("not enough alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("http://foo.bar.de/oddlyspecific"))
	fwhandler.Reset()
	bh.Consume(&e1)

	if len(fwhandler.GetEntries()) != 1 {
		t.Fatalf("not enough alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("https://foo.bar.de/oddlyspecific"))
	fwhandler.Reset()
	bh.Consume(&e1)

	if len(fwhandler.GetEntries()) != 0 {
		t.Fatalf("too many alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("https://foo.bar.com/oddlyspecific"))
	fwhandler.Reset()
	bh.Consume(&e1)

	if len(fwhandler.GetEntries()) != 0 {
		t.Fatalf("too many alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("/"))
	fwhandler.Reset()
	bh.Consume(&e1)

	if len(fwhandler.GetEntries()) != 0 {
		t.Fatalf("too many alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("/oddlyspecific"))
	fwhandler.Reset()
	bh.Consume(&e2)

	if len(fwhandler.GetEntries()) != 1 {
		t.Fatalf("not enough alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("foo.bar.de/oddlyspecific"))
	fwhandler.Reset()
	bh.Consume(&e2)

	if len(fwhandler.GetEntries()) != 1 {
		t.Fatalf("not enough alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("http://foo.bar.de/oddlyspecific"))
	fwhandler.Reset()
	bh.Consume(&e2)

	if len(fwhandler.GetEntries()) != 1 {
		t.Fatalf("not enough alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("https://foo.bar.de/oddlyspecific"))
	fwhandler.Reset()
	bh.Consume(&e2)

	if len(fwhandler.GetEntries()) != 0 {
		t.Fatalf("too many alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("https://foo.bar.com/oddlyspecific"))
	fwhandler.Reset()
	bh.Consume(&e2)

	if len(fwhandler.GetEntries()) != 0 {
		t.Fatalf("too many alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("/"))
	fwhandler.Reset()
	bh.Consume(&e2)

	if len(fwhandler.GetEntries()) != 0 {
		t.Fatalf("too many alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("/oddlyspecific"))
	fwhandler.Reset()
	bh.Consume(&e3)

	if len(fwhandler.GetEntries()) != 1 {
		t.Fatalf("not enough alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("foo.bar.de/oddlyspecific"))
	fwhandler.Reset()
	bh.Consume(&e3)

	if len(fwhandler.GetEntries()) != 0 {
		t.Fatalf("too many alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("http://foo.bar.de/oddlyspecific"))
	fwhandler.Reset()
	bh.Consume(&e3)

	if len(fwhandler.GetEntries()) != 0 {
		t.Fatalf("too many alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("https://foo.bar.de/oddlyspecific"))
	fwhandler.Reset()
	bh.Consume(&e3)

	if len(fwhandler.GetEntries()) != 0 {
		t.Fatalf("too many alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("https://foo.bar.com/oddlyspecific"))
	fwhandler.Reset()
	bh.Consume(&e3)

	if len(fwhandler.GetEntries()) != 0 {
		t.Fatalf("too many alerts: %d", len(fwhandler.GetEntries()))
	}

	bf = bloom.Initialize(100000, 0.0000001)
	bf.Add([]byte("/"))
	fwhandler.Reset()
	bh.Consume(&e3)

	if len(fwhandler.GetEntries()) != 0 {
		t.Fatalf("too many alerts: %d", len(fwhandler.GetEntries()))
	}
}

func TestBloomHandlerBlacklistedSkip(t *testing.T) {
	e1 := types.Entry{
		SrcIP:      "10.0.0.1",
		SrcPort:    23545,
		DestIP:     "10.0.0.2",
		DestPort:   80,
		Timestamp:  time.Now().Format(types.SuricataTimestampFormat),
		EventType:  "http",
		Proto:      "TCP",
		HTTPHost:   "foo.bar.de",
		HTTPUrl:    "http://foo.bar.de/oddlyspecific",
		HTTPMethod: "GET",
	}
	eve1 := types.EveEvent{
		EventType: e1.EventType,
		SrcIP:     e1.SrcIP,
		SrcPort:   int(e1.SrcPort),
		DestIP:    e1.DestIP,
		DestPort:  int(e1.DestPort),
		Proto:     e1.Proto,
		HTTP: &types.HTTPEvent{
			Hostname: e1.HTTPHost,
			URL:      e1.HTTPUrl,
		},
	}
	json1, err := json.Marshal(eve1)
	if err != nil {
		log.Warn(err)
	} else {
		e1.JSONLine = string(json1)
	}
	e2 := types.Entry{
		SrcIP:      "10.0.0.1",
		SrcPort:    23545,
		DestIP:     "10.0.0.2",
		DestPort:   80,
		Timestamp:  time.Now().Format(types.SuricataTimestampFormat),
		EventType:  "http",
		Proto:      "TCP",
		HTTPHost:   "foo.bar.de",
		HTTPUrl:    "/",
		HTTPMethod: "GET",
	}
	eve2 := types.EveEvent{
		EventType: e2.EventType,
		SrcIP:     e2.SrcIP,
		SrcPort:   int(e2.SrcPort),
		DestIP:    e2.DestIP,
		DestPort:  int(e2.DestPort),
		Proto:     e2.Proto,
		HTTP: &types.HTTPEvent{
			Hostname: e2.HTTPHost,
			URL:      e2.HTTPUrl,
		},
	}
	json2, err := json.Marshal(eve2)
	if err != nil {
		log.Warn(err)
	} else {
		e2.JSONLine = string(json2)
	}

	b1 := bloom.Initialize(1000, 0.0001)
	b1.Add([]byte("/oddlyspecific"))
	b1.Add([]byte("/"))
	b1File, err := ioutil.TempFile("", "blist")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(b1File.Name())
	b1.Write(b1File)
	b1File.Close()

	dbChan := make(chan types.Entry, 5)
	dbWritten := make([]types.Entry, 0)
	consumeWaitChan := make(chan bool)
	go func() {
		for e := range dbChan {
			dbWritten = append(dbWritten, e)
		}
		close(consumeWaitChan)
	}()

	// handler to receive forwarded events
	fwhandler := &CollectorHandler{
		Entries: make(map[string]bool),
	}

	bh, err := MakeBloomHandlerFromFile(b1File.Name(), false, dbChan, fwhandler, "FOO BAR", []string{"/"})
	if err != nil {
		t.Fatal(err)
	}

	bh.Consume(&e1)
	if len(fwhandler.GetEntries()) != 1 {
		t.Fatalf("not enough alerts: %d", len(fwhandler.GetEntries()))
	}

	fwhandler.Reset()
	bh.Consume(&e2)

	if len(fwhandler.GetEntries()) != 0 {
		t.Fatalf("should not create alert but got %d", len(fwhandler.GetEntries()))
	}

	bh.Consume(&e1)
	if len(fwhandler.GetEntries()) != 1 {
		t.Fatalf("not enough alerts: %d", len(fwhandler.GetEntries()))
	}
}

func TestBloomHandlerInvalidDNS(t *testing.T) {
	// initalize Bloom filter and fill with 'interesting' values
	bf := bloom.Initialize(100000, 0.0000001)

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
	e := makeBloomDNSEvent("foobar")
	e.DNSType = "foobar"
	bf.Add([]byte(e.DNSRRName))

	hook := test.NewGlobal()

	bh.Consume(&e)

	entries := hook.AllEntries()
	if len(entries) < 1 {
		t.Fatal("missing log entries")
	}
	if entries[0].Message != "invalid DNS type: 'foobar'" {
		t.Fatal("wrong log entry for invalid DNS type")
	}
}
