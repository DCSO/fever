package input

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/DCSO/fever/types"

	log "github.com/sirupsen/logrus"
)

func TestSocketInput(t *testing.T) {
	dir, err := ioutil.TempDir("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tmpfn := filepath.Join(dir, fmt.Sprintf("t%d", rand.Int63()))

	evChan := make(chan types.Entry)
	events := make([]string, 1000)

	is, err := MakeSocketInput(tmpfn, evChan, false)
	if err != nil {
		t.Fatal(err)
	}
	is.Run()

	submitDone := make(chan bool)
	collectDone := make(chan bool)

	go func() {
		c, err := net.Dial("unix", tmpfn)
		if err != nil {
			log.Println(err)
		}
		for i := 0; i < 1000; i++ {
			events[i] = makeEveEvent([]string{"http", "dns", "foo"}[rand.Intn(3)], i)
			c.Write([]byte(events[i]))
			c.Write([]byte("\n"))
		}
		c.Close()
		close(submitDone)
	}()

	coll := make([]types.Entry, 0)
	go func() {
		for i := 0; i < 1000; i++ {
			e := <-evChan
			coll = append(coll, e)
		}
		close(collectDone)
	}()

	<-submitDone
	<-collectDone
	ch := make(chan bool)
	is.Stop(ch)
	<-ch

	if len(coll) != 1000 {
		t.Fatalf("unexpected number of items read from socket: %d != 1000",
			len(coll))
	}
	for i := 0; i < 1000; i++ {
		var checkEvent types.EveEvent
		json.Unmarshal([]byte(events[i]), &checkEvent)
		if coll[i].EventType != checkEvent.EventType {
			t.Fatalf("wrong event type for test event %d: %s != %s", i,
				coll[i].EventType, checkEvent.EventType)
		}
	}
}
