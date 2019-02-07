package processing

// DCSO FEVER
// Copyright (c) 2017, 2019, DCSO GmbH

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"
)

const (
	numTestEvents = 100000
)

func makeDNSEvent() types.Entry {
	e := types.Entry{
		SrcIP:     fmt.Sprintf("10.0.0.%d", rand.Intn(5)+1),
		SrcPort:   53,
		DestIP:    fmt.Sprintf("10.0.0.%d", rand.Intn(50)),
		DestPort:  []int64{11, 12, 13, 14, 15}[rand.Intn(5)],
		Timestamp: time.Now().Format(types.SuricataTimestampFormat),
		EventType: "DNS",
		Proto:     "TCP",
		DNSRCode:  []string{"NOERROR", "NXDOMAIN"}[rand.Intn(2)],
		DNSRData:  fmt.Sprintf("10.%d.0.%d", rand.Intn(50), rand.Intn(50)+100),
		DNSRRName: fmt.Sprintf("%s.com", util.RandStringBytesMaskImprSrc(4)),
		DNSRRType: "answer",
	}
	return e
}

func TestDNSAggregator(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	outChan := make(chan types.Entry)
	consumeWaitChan := make(chan bool)
	closeChan := make(chan bool)

	f := MakeDNSAggregator(1*time.Second, outChan)

	daTypes := f.GetEventTypes()
	if len(daTypes) != 1 {
		t.Fatal("DNS aggregation handler should only claim one type")
	}
	if daTypes[0] != "dns" {
		t.Fatal("DNS aggregation handler should only claim 'dns' type")
	}
	if f.GetName() != "DB DNS aggregator" {
		t.Fatal("DNS aggregation handler has wrong name")
	}

	var observedLock sync.Mutex
	observedSituations := make(map[string]int)
	observedDomains := make(map[string]bool)
	setupSituations := make(map[string]int)
	setupDomains := make(map[string]bool)

	go func() {
		var buf bytes.Buffer
		for {
			select {
			case e := <-outChan:
				var out AggregateDNSEvent
				err := json.Unmarshal([]byte(e.JSONLine), &out)
				if err != nil {
					t.Fail()
				}
				for _, v := range out.DNS.Details {
					buf.Write([]byte(out.DNS.Rrname))
					buf.Write([]byte(v.Rrtype))
					buf.Write([]byte(v.Rdata))
					buf.Write([]byte(v.Rcode))
					observedLock.Lock()
					observedSituations[buf.String()]++
					observedLock.Unlock()
					observedDomains[out.DNS.Rrname] = true
					buf.Reset()
				}
			case <-closeChan:
				close(consumeWaitChan)
				return
			}
		}
	}()

	f.Run()
	for i := 0; i < numTestEvents; i++ {
		var buf bytes.Buffer
		ev := makeDNSEvent()
		buf.Write([]byte(ev.DNSRRName))
		buf.Write([]byte(ev.DNSRRType))
		buf.Write([]byte(ev.DNSRData))
		buf.Write([]byte(ev.DNSRCode))
		setupSituations[buf.String()]++
		setupDomains[ev.DNSRRName] = true
		buf.Reset()
		f.Consume(&ev)
	}

	go func() {
		for {
			observedLock.Lock()
			if len(setupSituations) <= len(observedSituations) {
				observedLock.Unlock()
				break
			}
			observedLock.Unlock()
			time.Sleep(100 * time.Millisecond)

		}
		close(closeChan)
	}()

	<-consumeWaitChan
	close(outChan)

	waitChan := make(chan bool)
	f.Stop(waitChan)
	<-waitChan

	if len(setupSituations) != len(observedSituations) {
		t.Fatalf("results have different dimensions: %d/%d", len(setupSituations),
			len(observedSituations))
	}
	for k, v := range setupSituations {
		if _, ok := observedSituations[k]; !ok {
			t.Fatalf("missing key: %s", k)
		}
		v2 := observedSituations[k]
		if v2 != v {
			t.Fatalf("mismatching counts for key %s: %d/%d", k, v, v2)
		}
	}
	for k, v := range observedSituations {
		if _, ok := setupSituations[k]; !ok {
			t.Fatalf("missing key: %s", k)
		}
		v2 := setupSituations[k]
		if v2 != v {
			t.Fatalf("mismatching counts for key %s: %d/%d", k, v, v2)
		}
	}
	if len(setupDomains) != len(observedDomains) {
		t.Fatalf("results have different dimensions: %d/%d", len(setupDomains),
			len(observedDomains))
	}
	for k := range observedDomains {
		if _, ok := setupDomains[k]; !ok {
			t.Fatalf("missing key: %s", k)
		}
	}
}
