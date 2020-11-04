package processing

// DCSO FEVER
// Copyright (c) 2020, DCSO GmbH

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DCSO/fever/types"
)

const (
	numOfProfiledFlowItems = 10000
)

func makeFlowProfilerEvent() types.Entry {
	e := types.Entry{
		SrcIP:         fmt.Sprintf("10.0.0.%d", rand.Intn(250)),
		SrcPort:       []int64{1, 2, 3, 4, 5}[rand.Intn(5)],
		DestIP:        fmt.Sprintf("10.0.0.%d", rand.Intn(250)),
		DestPort:      []int64{11, 12, 13, 14, 15}[rand.Intn(5)],
		Timestamp:     time.Now().Format(types.SuricataTimestampFormat),
		EventType:     "flow",
		Proto:         "TCP",
		AppProto:      []string{"foo", "bar", "baz"}[rand.Intn(3)],
		BytesToClient: int64(rand.Intn(10000)),
		BytesToServer: int64(rand.Intn(10000)),
		PktsToClient:  int64(rand.Intn(100)),
		PktsToServer:  int64(rand.Intn(100)),
	}
	jsonBytes, _ := json.Marshal(e)
	e.JSONLine = string(jsonBytes)
	return e
}

type flowProfilerTestSubmitter struct {
	sync.Mutex
	Values [][]byte
}

func (fpts *flowProfilerTestSubmitter) SubmitWithHeaders(rawData []byte, key string, contentType string, myHeaders map[string]string) {
	fpts.Lock()
	defer fpts.Unlock()
	fpts.Values = append(fpts.Values, rawData)
}

func (fpts *flowProfilerTestSubmitter) Submit(rawData []byte, key string, contentType string) {
	fpts.Lock()
	defer fpts.Unlock()
	fpts.Values = append(fpts.Values, rawData)
}

func (fpts *flowProfilerTestSubmitter) UseCompression() {
	// pass
}

func (fpts *flowProfilerTestSubmitter) Finish() {
	// pass
}

// TestFlowProfiler checks whether flow profiles are generated correctly.
// To do this, it consumes a set of example events with randomized event types
// and sizes, generates a reference set of statistics and then compares it to
// the values submitted to a test submitter which simply stores these values.
func TestFlowProfiler(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	myMap := make(map[string]ProtoProfile)
	seenProfile := make(map[string]ProtoProfile)

	feedWaitChan := make(chan bool)

	s := &flowProfilerTestSubmitter{
		Values: make([][]byte, 0),
	}

	f, err := MakeFlowProfiler(1*time.Second, s)
	if err != nil {
		t.Fatal(err)
	}

	f.Run()

	for i := 0; i < numOfProfiledFlowItems; i++ {
		ev := makeFlowProfilerEvent()
		myProfile := myMap[ev.AppProto]
		myProfile.BytesToClt += uint64(ev.BytesToClient)
		myProfile.BytesToSrv += uint64(ev.BytesToServer)
		myProfile.PacketsToClt += uint64(ev.PktsToClient)
		myProfile.PacketsToSrv += uint64(ev.PktsToServer)
		myMap[ev.AppProto] = myProfile
		f.Consume(&ev)
	}

	go func() {
		r := regexp.MustCompile(`proto=(?P<Proto>[^ ]+) flowbytestoclient=(?P<fbtc>[0-9]+),flowbytestoserver=(?P<fbts>[0-9]+),flowpktstoclient=(?P<fptc>[0-9]+),flowpktstoserver=(?P<fpts>[0-9]+)`)
		for {
			s.Lock()
			found := 0
			for _, v := range s.Values {
				for _, proto := range []string{"foo", "bar", "baz"} {
					if strings.Contains(string(v), fmt.Sprintf("proto=%s flowbytestoclient=0,flowbytestoserver=0,flowpktstoclient=0,flowpktstoserver=0", proto)) {
						found++
					}
				}
			}
			s.Unlock()
			if found == 3 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		s.Lock()
		for _, v := range s.Values {
			sm := r.FindStringSubmatch(string(v))
			if sm == nil {
				continue
			}
			p := seenProfile[sm[1]]
			intV, err := strconv.ParseUint(sm[2], 10, 64)
			if err == nil {
				p.BytesToClt += intV
			}
			intV, err = strconv.ParseUint(sm[3], 10, 64)
			if err == nil {
				p.BytesToSrv += intV
			}
			intV, err = strconv.ParseUint(sm[4], 10, 64)
			if err == nil {
				p.PacketsToClt += intV
			}
			intV, err = strconv.ParseUint(sm[5], 10, 64)
			if err == nil {
				p.PacketsToSrv += intV
			}
			seenProfile[sm[1]] = p
		}
		s.Unlock()
		close(feedWaitChan)
	}()

	<-feedWaitChan

	consumeWaitChan := make(chan bool)
	f.Stop(consumeWaitChan)
	<-consumeWaitChan

	if !reflect.DeepEqual(myMap, seenProfile) {
		t.Fatal("different result for test")
	}
}
