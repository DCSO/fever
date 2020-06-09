package processing

// DCSO FEVER
// Copyright (c) 2020, DCSO GmbH

import (
	"encoding/json"
	"math/rand"
	"testing"
	"time"

	"github.com/DCSO/fever/types"
	log "github.com/sirupsen/logrus"
)

type MockHostNamer struct{}

func (m *MockHostNamer) GetHostname(ipAddr string) ([]string, error) {
	return []string{"foo.bar", "foo.baz"}, nil
}

func (m *MockHostNamer) Flush() {}

func makeRDNSEvent() types.Entry {
	e := types.Entry{
		SrcIP:     "8.8.8.8",
		SrcPort:   int64(rand.Intn(60000) + 1025),
		DestIP:    "8.8.8.8",
		DestPort:  53,
		Timestamp: time.Now().Format(types.SuricataTimestampFormat),
		EventType: "http",
		Proto:     "TCP",
	}
	eve := types.EveEvent{
		Timestamp: &types.SuriTime{
			Time: time.Now(),
		},
		EventType: e.EventType,
		SrcIP:     e.SrcIP,
		SrcPort:   int(e.SrcPort),
		DestIP:    e.DestIP,
		DestPort:  int(e.DestPort),
		Proto:     e.Proto,
	}
	json, err := json.Marshal(eve)
	if err != nil {
		log.Warn(err)
	} else {
		e.JSONLine = string(json)
	}
	return e
}

type SrcHostResponse struct {
	Evidence []struct {
		Hostname string `json:"rdns"`
	} `json:"src_host"`
}

type DstHostResponse struct {
	Evidence []struct {
		Hostname string `json:"rdns"`
	} `json:"dest_host"`
}

func TestRDNSHandler(t *testing.T) {
	hn := MockHostNamer{}
	rdnsh := MakeRDNSHandler(&hn)

	e := makeRDNSEvent()

	err := rdnsh.Consume(&e)
	if err != nil {
		t.Fatal(err)
	}

	var srchosts SrcHostResponse
	err = json.Unmarshal([]byte(e.JSONLine), &srchosts)
	if err != nil {
		t.Fatal(err)
	}
	if len(srchosts.Evidence) != 2 {
		t.Fatalf("src hosts length is not 2: length %d", len(srchosts.Evidence))
	}
	if srchosts.Evidence[0].Hostname != "foo.bar" {
		t.Fatalf("wrong hostname:%s", srchosts.Evidence[0].Hostname)
	}
	if srchosts.Evidence[1].Hostname != "foo.baz" {
		t.Fatalf("wrong hostname:%s", srchosts.Evidence[1].Hostname)
	}

	var desthosts DstHostResponse
	err = json.Unmarshal([]byte(e.JSONLine), &desthosts)
	if err != nil {
		t.Fatal(err)
	}
	if len(desthosts.Evidence) != 2 {
		t.Fatalf("dest hosts length is not 2: length %d", len(desthosts.Evidence))
	}
	if desthosts.Evidence[0].Hostname != "foo.bar" {
		t.Fatalf("wrong hostname:%s", desthosts.Evidence[0].Hostname)
	}
	if desthosts.Evidence[1].Hostname != "foo.baz" {
		t.Fatalf("wrong hostname:%s", desthosts.Evidence[1].Hostname)
	}
}
