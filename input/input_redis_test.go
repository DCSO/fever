package input

// DCSO FEVER
// Copyright (c) 2017, 2019, DCSO GmbH

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/DCSO/fever/types"

	"github.com/garyburd/redigo/redis"
	log "github.com/sirupsen/logrus"
	"github.com/stvp/tempredis"
)

const nofRedisTests = 10000

func makeEveEvent(etype string, number int) string {
	eve := types.EveEvent{
		EventType: etype,
		FlowID:    int64(number),
		SrcIP:     fmt.Sprintf("10.0.0.%d", number),
		SrcPort:   []int{11, 12, 13, 14, 15}[rand.Intn(5)],
		DestIP:    fmt.Sprintf("10.0.0.%d", rand.Intn(50)),
		DestPort:  []int{11, 12, 13, 14, 15}[rand.Intn(5)],
		Proto:     []string{"TCP", "UDP"}[rand.Intn(2)],
	}
	json, err := json.Marshal(eve)
	if err != nil {
		panic(err)
	}
	return string(json)
}

type byID []types.Entry

func (a byID) Len() int      { return len(a) }
func (a byID) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a byID) Less(i, j int) bool {
	var ie, je types.EveEvent
	err := json.Unmarshal([]byte(a[i].JSONLine), &ie)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal([]byte(a[j].JSONLine), &je)
	if err != nil {
		log.Fatal(err)
	}
	return ie.FlowID < je.FlowID
}

func _TestRedisInput(t *testing.T, usePipelining bool, sock string) {
	s, err := tempredis.Start(tempredis.Config{
		"unixsocket": sock,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Term()

	client, err := redis.Dial("unix", s.Socket())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	events := make([]string, nofRedisTests)

	var wg sync.WaitGroup
	wg.Add(1)
	go func(myWg *sync.WaitGroup) {
		defer myWg.Done()
		for i := 0; i < nofRedisTests; i++ {
			events[i] = makeEveEvent([]string{"http", "dns", "foo"}[rand.Intn(3)], i)
			client.Do("LPUSH", "suricata", events[i])
		}
	}(&wg)
	wg.Wait()

	evChan := make(chan types.Entry)

	coll := make([]types.Entry, 0)
	wg.Add(1)
	go func(myWg *sync.WaitGroup) {
		defer myWg.Done()
		i := 0
		for e := range evChan {
			coll = append(coll, e)
			if i == nofRedisTests-1 {
				return
			}
			i++
		}
	}(&wg)

	ri, err := MakeRedisInputSocket(s.Socket(), evChan, 500)
	ri.UsePipelining = usePipelining
	if err != nil {
		t.Fatal(err)
	}
	ri.Run()

	wg.Wait()

	stopChan := make(chan bool)
	ri.Stop(stopChan)
	<-stopChan
	close(evChan)

	sort.Sort(byID(coll))

	if len(coll) != nofRedisTests {
		t.Fatalf("unexpected number of items read from Redis queue: %d != %d",
			len(coll), nofRedisTests)
	}
	for i := 0; i < nofRedisTests; i++ {
		var checkEvent types.EveEvent
		err := json.Unmarshal([]byte(events[i]), &checkEvent)
		if err != nil {
			t.Fatal(err)
		}
		if coll[i].EventType != checkEvent.EventType {
			t.Fatalf("wrong event type for test event %d: %s != %s", i,
				coll[i].EventType, checkEvent.EventType)
		}
	}
}

func TestRedisInputWithPipelining(t *testing.T) {
	dir, err := ioutil.TempDir("", "test")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tmpfn := filepath.Join(dir, "withPipe.sock")
	_TestRedisInput(t, true, tmpfn)
}

func TestRedisInputNoPipelining(t *testing.T) {
	dir, err := ioutil.TempDir("", "test")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tmpfn := filepath.Join(dir, "withPipe.sock")
	_TestRedisInput(t, false, tmpfn)
}

func _TestRedisGone(t *testing.T, usePipelining bool, sock string) {
	s, err := tempredis.Start(tempredis.Config{
		"unixsocket": sock,
	})
	if err != nil {
		t.Fatal(err)
	}

	evChan := make(chan types.Entry)
	ri, err := MakeRedisInputSocket(s.Socket(), evChan, 500)
	ri.UsePipelining = usePipelining
	if err != nil {
		t.Fatal(err)
	}
	ri.Run()

	time.Sleep(2 * time.Second)

	s.Term()

	s, err = tempredis.Start(tempredis.Config{
		"unixsocket": sock,
	})
	if err != nil {
		t.Fatal(err)
	}

	client, err := redis.Dial("unix", s.Socket())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	events := make([]string, nofRedisTests)

	var wg sync.WaitGroup
	go func() {
		for i := 0; i < nofRedisTests; i++ {
			events[i] = makeEveEvent([]string{"http", "dns", "foo"}[rand.Intn(3)], i)
			client.Do("LPUSH", "suricata", events[i])
		}
	}()

	coll := make([]types.Entry, 0)
	wg.Add(1)
	go func(myWg *sync.WaitGroup) {
		defer myWg.Done()
		i := 0
		for e := range evChan {
			coll = append(coll, e)
			if i == nofRedisTests-1 {
				return
			}
			i++
		}
	}(&wg)

	wg.Wait()

	stopChan := make(chan bool)
	ri.Stop(stopChan)
	<-stopChan
	close(evChan)

	sort.Sort(byID(coll))

	if len(coll) != nofRedisTests {
		t.Fatalf("unexpected number of items read from Redis queue: %d != %d",
			len(coll), nofRedisTests)
	}
	for i := 0; i < nofRedisTests; i++ {
		var checkEvent types.EveEvent
		err := json.Unmarshal([]byte(events[i]), &checkEvent)
		if err != nil {
			t.Fatal(err)
		}
		if coll[i].EventType != checkEvent.EventType {
			t.Fatalf("wrong event type for test event %d: %s != %s", i,
				coll[i].EventType, checkEvent.EventType)
		}
	}
}

func TestRedisGoneWithPipelining(t *testing.T) {
	dir, err := ioutil.TempDir("", "test")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tmpfn := filepath.Join(dir, "withPipe.sock")
	_TestRedisGone(t, true, tmpfn)
}

func TestRedisGoneNoPipelining(t *testing.T) {
	dir, err := ioutil.TempDir("", "test")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tmpfn := filepath.Join(dir, "withPipe.sock")
	_TestRedisGone(t, false, tmpfn)
}
