package processing

// DCSO FEVER
// Copyright (c) 2020, 2021, DCSO GmbH

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/DCSO/fever/types"

	"github.com/buger/jsonparser"
)

type HeartbeatTestFwdHandler struct {
	Entries []types.Entry
	Lock    sync.Mutex
}

func (h *HeartbeatTestFwdHandler) Consume(e *types.Entry) error {
	h.Lock.Lock()
	defer h.Lock.Unlock()
	h.Entries = append(h.Entries, *e)
	return nil
}

func (h *HeartbeatTestFwdHandler) GetEventTypes() []string {
	return []string{"*"}
}

func (h *HeartbeatTestFwdHandler) GetName() string {
	return "Heartbeat Injector Forwarding Test Handler"
}

func TestHeartbeatInjectorInvalidTime(t *testing.T) {
	hbth := HeartbeatTestFwdHandler{
		Entries: make([]types.Entry, 0),
	}

	_, err := MakeHeartbeatInjector(&hbth, []string{"foo"}, []string{})
	if err == nil {
		t.Fatal("invalid time not caught")
	}
}

func TestHeartbeatInjectorInvalidAlertTime(t *testing.T) {
	hbth := HeartbeatTestFwdHandler{
		Entries: make([]types.Entry, 0),
	}

	_, err := MakeHeartbeatInjector(&hbth, []string{}, []string{"foo"})
	if err == nil {
		t.Fatal("invalid time not caught")
	}
}

func TestHeartbeatInjector(t *testing.T) {
	hbth := HeartbeatTestFwdHandler{
		Entries: make([]types.Entry, 0),
	}

	now := time.Now()
	ctime := []string{now.Format("15:04")}

	hbi, err := MakeHeartbeatInjector(&hbth, ctime, []string{})
	if err != nil {
		t.Fatal(err)
	}

	hbi.Run()
	for {
		hbth.Lock.Lock()
		if len(hbth.Entries) > 0 {
			hbth.Lock.Unlock()
			break
		}
		hbth.Lock.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
	hbi.Stop()

	hbJSON := hbth.Entries[0].JSONLine

	expectedHost := fmt.Sprintf("test-%d-%02d-%02d.vast",
		now.Year(), now.Month(), now.Day())
	seenHost, err := jsonparser.GetString([]byte(hbJSON), "http", "hostname")
	if err != nil {
		t.Fatal(err)
	}
	if seenHost != expectedHost {
		t.Fatalf("wrong hostname for heartbeat: %s", seenHost)
	}
}

func TestHeartbeatAlertInjector(t *testing.T) {
	hbth := HeartbeatTestFwdHandler{
		Entries: make([]types.Entry, 0),
	}

	now := time.Now()
	atime := []string{now.Format("15:04")}

	hbi, err := MakeHeartbeatInjector(&hbth, []string{}, atime)
	if err != nil {
		t.Fatal(err)
	}

	hbi.Run()
	for {
		hbth.Lock.Lock()
		if len(hbth.Entries) > 0 {
			hbth.Lock.Unlock()
			break
		}
		hbth.Lock.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
	hbi.Stop()

	hbJSON := hbth.Entries[0].JSONLine

	sig, err := jsonparser.GetString([]byte(hbJSON), "alert", "signature")
	if err != nil {
		t.Fatal(err)
	}
	if sig != "DCSO FEVER TEST alert" {
		t.Fatalf("wrong signature for test alert: %s", sig)
	}
}
