package util

// DCSO FEVER
// Copyright (c) 2020, DCSO GmbH

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/buger/jsonparser"

	log "github.com/sirupsen/logrus"
)

func makeTestHTTPEvent(host string, url string) types.Entry {
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
			Hostname:        e.HTTPHost,
			URL:             e.HTTPUrl,
			HTTPMethod:      "GET",
			Status:          200,
			Length:          19000,
			Protocol:        "HTTP/1.1",
			HTTPContentType: "application/html",
			HTTPUserAgent:   "Go",
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

type TestAlertJSONProviderHost struct{}

func (a TestAlertJSONProviderHost) GetAlertJSON(inputEvent types.Entry,
	prefix string, ioc string) ([]byte, error) {
	sig := fmt.Sprintf("%s Possibly bad HTTP Host match for '%s'", prefix, ioc)
	val, err := EscapeJSON(sig)
	if err != nil {
		return nil, err
	}
	v, err := jsonparser.Set([]byte("{}"), val, "signature")
	return v, err
}

type TestAlertJSONProviderURLPath struct{}

func (a TestAlertJSONProviderURLPath) GetAlertJSON(inputEvent types.Entry,
	prefix string, ioc string) ([]byte, error) {
	sig := fmt.Sprintf("%s Possibly bad HTTP Path match for '%s' in '%s'",
		prefix, ioc, inputEvent.HTTPUrl)
	val, err := EscapeJSON(sig)
	if err != nil {
		return nil, err
	}
	v, err := jsonparser.Set([]byte("{}"), val, "signature")
	return v, err
}

func checkAlertifierAlerts(t *testing.T, a *types.Entry, msg string, ioc string) {
	var resAlert types.EveEvent
	if err := json.Unmarshal([]byte(a.JSONLine), &resAlert); err != nil {
		t.Fatal(err)
	}
	if resAlert.Alert.Signature != msg {
		t.Fatalf("wrong signature ('%s' <-> '%s')", resAlert.Alert.Signature, msg)
	}
	if resAlert.ExtraInfo == nil {
		t.Fatalf("missing _extra in '%s'", string(a.JSONLine))
	}
	if resAlert.ExtraInfo.VastIOC != ioc {
		t.Fatalf("wrong ioc ('%s' <-> '%s')", resAlert.ExtraInfo.VastIOC, ioc)
	}
}

func testExtraModifier(inputAlert *types.Entry, ioc string) error {
	iocEscaped, err := EscapeJSON(ioc)
	if err != nil {
		return err
	}
	val, err := jsonparser.Set([]byte(inputAlert.JSONLine), iocEscaped,
		"_extra", "vast-ioc")
	if err != nil {
		return err
	}
	inputAlert.JSONLine = string(val)
	return nil
}

func TestAlertifierSimple(t *testing.T) {
	a := MakeAlertifier("TEST")
	a.SetExtraModifier(testExtraModifier)
	a.RegisterMatchType("http_host", TestAlertJSONProviderHost{})
	a.RegisterMatchType("http_path", TestAlertJSONProviderURLPath{})
	e := makeTestHTTPEvent("foo.bar", "http://foo.bar/baz")
	alert, err := a.MakeAlert(e, "foo.bar", "http_host")
	if err != nil {
		t.Fatal(err)
	}
	checkAlertifierAlerts(t, alert, "TEST Possibly bad HTTP Host match "+
		"for 'foo.bar'", "foo.bar")
	alert, err = a.MakeAlert(e, "foo.bar", "http_path")
	if err != nil {
		t.Fatal(err)
	}
	checkAlertifierAlerts(t, alert, "TEST Possibly bad HTTP Path match for "+
		"'foo.bar' in 'http://foo.bar/baz'", "foo.bar")
}

func TestAlertifierUnknownMatchtype(t *testing.T) {
	a := MakeAlertifier("TEST")
	a.SetExtraModifier(testExtraModifier)
	e := makeTestHTTPEvent("foo.bar", "http://foo.bar/baz")
	_, err := a.MakeAlert(e, "foo.bar", "nonexistant")
	if err == nil {
		t.Fatal("nonexistant matchType did not trigger an error")
	}
}
