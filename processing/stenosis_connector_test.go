package processing

// DCSO FEVER
// Copyright (c) 2020, DCSO GmbH

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DCSO/fever/stenosis/task"
	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"
)

// Currently unused. Keeping this here for future randomized tests.
// Tests are rudimentary for now.
// func makeAlertEntry(t *test.T, myTime time.Time, srcIP, dstIP string, srcPort, dstPort int) types.Entry {
// 	eve := types.EveEvent{
// 		SrcIP:    srcIP,
// 		DestIP:   dstIP,
// 		SrcPort:  srcPort,
// 		DestPort: dstPort,
// 		Timestamp: &types.SuriTime{
// 			Time: myTime,
// 		},
// 		Flow: &types.EveFlowEvent{
// 			Start: &types.SuriTime{
// 				Time: myTime.Add(defaultStenosisTimeBracket),
// 			},
// 		},
// 		ExtraInfo: &types.ExtraInfo{
// 			BloomIOC: "foobar",
// 		},
// 	}
// 	entry := &types.Entry{
// 		SrcIP:     eve.SrcIP,
// 		SrcPort:   int64(eve.SrcPort),
// 		DestIP:    eve.DestIP,
// 		DestPort:  int64(eve.DestPort),
// 		Timestamp: myTime.Format(types.SuricataTimestampFormat),
// 		EventType: "alert",
// 		Proto:     "TCP",
// 	}
// 	jsonData, err := json.Marshal(eve)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	entry.JSONLine = string(jsonData)
// }

func _TestStenosisQueryRegularSuccessForwarded(t *testing.T, ifaceSetting string) []string {
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

	// prepare slice to hold collected strings
	coll := make([]string, 0)

	// setup comms channels
	clCh := make(chan bool)
	cldCh := make(chan bool)

	// start socket consumer
	var wg sync.WaitGroup
	wg.Add(1)
	go consumeSocket(inputListener, clCh, cldCh, t, &coll, &wg)

	grpcServer, _ := newMockGRPCServer(mockGRPCServerTokenGenerateOption(func(*task.Query) string {
		return "FIXED_TOKEN_STRING"
	}))

	go func() {
		if err := grpcServer.ListenAndServe(); err != nil {
			t.Error(err)
		}
	}()

	// wait for server to become available
	for {
		time.Sleep(10 * time.Millisecond)
		if len(grpcServer.Addr()) > 0 {
			break
		}
	}

	notifyChan := make(chan types.Entry)
	// notifier := MakeFlowNotifier(notifyChan)

	// start forwarding handler
	fh := MakeForwardHandler(5, tmpfn)
	// this needs to be started first so the channel is created
	fh.Run()

	// fh.EnableStenosis(apiServer.URL, 2*time.Second, notifyChan, nil)
	fh.EnableStenosis(grpcServer.Addr(), 2*time.Second, 10*time.Second,
		notifyChan, 10*time.Minute, nil, ifaceSetting)

	// make alert
	myTime, err := time.Parse(time.RFC3339, "2020-01-09T09:38:51+01:00")
	if err != nil {
		t.Fatal(err)
	}
	eve := types.EveEvent{
		SrcIP:     "192.168.2.42",
		DestIP:    "192.168.88.115",
		SrcPort:   43655,
		DestPort:  23,
		FlowID:    13,
		EventType: "alert",
		InIface:   "eth1",
		Timestamp: &types.SuriTime{
			Time: myTime,
		},
		Flow: &types.EveFlowEvent{
			Start: &types.SuriTime{
				Time: myTime.Add(defaultStenosisTimeBracket),
			},
		},
		ExtraInfo: &types.ExtraInfo{
			BloomIOC: "foobar",
		},
	}
	entry := &types.Entry{
		SrcIP:     eve.SrcIP,
		SrcPort:   int64(eve.SrcPort),
		DestIP:    eve.DestIP,
		DestPort:  int64(eve.DestPort),
		FlowID:    "13",
		Timestamp: myTime.Format(types.SuricataTimestampFormat),
		EventType: "alert",
		Proto:     "TCP",
		Iface:     "eth1",
	}
	jsonData, err := json.Marshal(eve)
	if err != nil {
		t.Fatal(err)
	}
	entry.JSONLine = string(jsonData)

	flowEve := types.EveEvent{
		SrcIP:     "192.168.2.42",
		DestIP:    "192.168.88.115",
		SrcPort:   43655,
		DestPort:  23,
		FlowID:    13,
		EventType: "flow",
		InIface:   "eth1",
		Timestamp: &types.SuriTime{
			Time: myTime,
		},
		Flow: &types.EveFlowEvent{
			Start: &types.SuriTime{
				Time: myTime.Add(defaultStenosisTimeBracket),
			},
		},
	}
	flowEntry := types.Entry{
		SrcIP:     eve.SrcIP,
		SrcPort:   int64(eve.SrcPort),
		DestIP:    eve.DestIP,
		DestPort:  int64(eve.DestPort),
		FlowID:    "13",
		Timestamp: myTime.Format(types.SuricataTimestampFormat),
		EventType: "flow",
		Proto:     "TCP",
		Iface:     "eth1",
	}
	jsonData, err = json.Marshal(flowEve)
	if err != nil {
		t.Fatal(err)
	}
	flowEntry.JSONLine = string(jsonData)

	// consume alert
	fh.Consume(entry)
	// send flow notification with matching flow ID to signal end of flow
	notifyChan <- flowEntry

	// stop forwarding handler
	scChan := make(chan bool)
	fh.Stop(scChan)
	<-scChan

	// we can now close this
	grpcServer.Close()

	// wait for socket consumer to receive all
	wg.Wait()

	return coll
}

func TestStenosisQueryRegularSuccessForwarded(t *testing.T) {
	coll := _TestStenosisQueryRegularSuccessForwarded(t, "*")
	if len(coll) != 1 {
		t.Fatalf("unexpected number of alerts: %d != 1", len(coll))
	}

	var eveOut types.EveOutEvent
	err := json.Unmarshal([]byte(coll[0]), &eveOut)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(coll[0], `"stenosis-info":`) {
		t.Fatalf("%v missing 'stenosis-info' string", coll[0])
	}
	if !strings.Contains(coll[0], `"token":`) {
		t.Fatalf("%v missing 'token' string", coll[0])
	}
	if !strings.Contains(coll[0], `"bloom-ioc"`) {
		t.Fatalf("%v missing 'bloom-ioc' string", coll[0])
	}
}

func TestStenosisQueryRegularSuccessForwardedWithIfaceOK(t *testing.T) {
	coll := _TestStenosisQueryRegularSuccessForwarded(t, "eth1")
	if len(coll) != 1 {
		t.Fatalf("unexpected number of alerts: %d != 1", len(coll))
	}

	var eveOut types.EveOutEvent
	err := json.Unmarshal([]byte(coll[0]), &eveOut)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(coll[0], `"stenosis-info":`) {
		t.Fatalf("%v missing 'stenosis-info' string", coll[0])
	}
	if !strings.Contains(coll[0], `"token":`) {
		t.Fatalf("%v missing 'token' string", coll[0])
	}
	if !strings.Contains(coll[0], `"bloom-ioc"`) {
		t.Fatalf("%v missing 'bloom-ioc' string", coll[0])
	}
}

func TestStenosisQueryRegularSuccessForwardedWithIfaceNonMatch(t *testing.T) {
	coll := _TestStenosisQueryRegularSuccessForwarded(t, "eth2")
	if len(coll) != 1 {
		t.Fatalf("unexpected number of alerts: %d != 1", len(coll))
	}

	var eveOut types.EveOutEvent
	err := json.Unmarshal([]byte(coll[0]), &eveOut)
	if err != nil {
		t.Fatal(err)
	}

	// In this case we do NOT want to see any results from a Stenosis call.
	if strings.Contains(coll[0], `"stenosis-info":`) {
		t.Fatalf("%v contains 'stenosis-info' string", coll[0])
	}
	if strings.Contains(coll[0], `"token":`) {
		t.Fatalf("%v contains 'token' string", coll[0])
	}
	if !strings.Contains(coll[0], `"bloom-ioc"`) {
		t.Fatalf("%v missing 'bloom-ioc' string", coll[0])
	}
}
