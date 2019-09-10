package util

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"bufio"
	"os"
	"reflect"
	"testing"

	"github.com/DCSO/fever/types"
)

var entries = []types.Entry{
	types.Entry{
		SrcIP:     "10.0.0.10",
		SrcPort:   53,
		DestIP:    "10.0.0.11",
		DestPort:  51323,
		Timestamp: "2017-03-06T06:54:06.047429+0000",
		EventType: "dns",
		Proto:     "UDP",
		JSONLine:  `{"timestamp":"2017-03-06T06:54:06.047429+0000","flow_id":4711,"in_iface":"enp2s0f1","event_type":"dns","vlan":61,"src_ip":"10.0.0.10","src_port":53,"dest_ip":"10.0.0.11","dest_port":51323,"proto":"UDP","dns":{"type":"answer","id":1,"rcode":"NOERROR","rrname":"test.test.local","rrtype":"A","ttl":2365,"rdata":"10.0.0.12"}}`,
		DNSRRName: "test.test.local",
		DNSRRType: "A",
		DNSRCode:  "NOERROR",
		DNSRData:  "10.0.0.12",
		DNSType:   "answer",
		FlowID:    "4711",
	},
	types.Entry{
		SrcIP:      "10.0.0.10",
		SrcPort:    80,
		DestIP:     "10.0.0.11",
		DestPort:   52914,
		Timestamp:  "2017-03-06T06:54:10.839668+0000",
		EventType:  "fileinfo",
		Proto:      "TCP",
		JSONLine:   `{"timestamp":"2017-03-06T06:54:10.839668+0000","flow_id":2323,"in_iface":"enp2s0f1","event_type":"fileinfo","vlan":91,"src_ip":"10.0.0.10","src_port":80,"dest_ip":"10.0.0.11","dest_port":52914,"proto":"TCP","http":{"hostname":"api.icndb.com","url":"\/jokes\/random?firstName=Chuck&lastName=Norris&limitTo=[nerdy]","http_user_agent":"Ruby","http_content_type":"application\/json","http_method":"GET","protocol":"HTTP\/1.1","status":200,"length":178},"app_proto":"http","fileinfo":{"filename":"\/jokes\/random","magic":"ASCII text, with no line terminators","state":"CLOSED","md5":"8d81d793b28b098e8623d47bae23cf44","stored":false,"size":176,"tx_id":0}}`,
		HTTPHost:   "api.icndb.com",
		HTTPUrl:    `/jokes/random?firstName=Chuck&lastName=Norris&limitTo=[nerdy]`,
		HTTPMethod: `GET`,
		FlowID:     "2323",
	},
	types.Entry{
		SrcIP:      "10.0.0.10",
		SrcPort:    24092,
		DestIP:     "10.0.0.11",
		DestPort:   80,
		Timestamp:  "2017-03-06T06:54:14.002504+0000",
		EventType:  "http",
		Proto:      "TCP",
		JSONLine:   `{"timestamp":"2017-03-06T06:54:14.002504+0000","flow_id":2134,"in_iface":"enp2s0f1","event_type":"http","vlan":72,"src_ip":"10.0.0.10","src_port":24092,"dest_ip":"10.0.0.11","dest_port":80,"proto":"TCP","tx_id":0,"http":{"hostname":"foobar","url":"\/scripts\/wpnbr.dll","http_content_type":"text\/xml","http_method":"POST","protocol":"HTTP\/1.1","status":200,"length":347}}`,
		HTTPHost:   "foobar",
		HTTPUrl:    `/scripts/wpnbr.dll`,
		HTTPMethod: `POST`,
		FlowID:     "2134",
	},
}

func TestJSONParseEVE(t *testing.T) {
	f, err := os.Open("testdata/jsonparse_eve.json")
	if err != nil {
		t.Fatalf(err.Error())
	}
	scanner := bufio.NewScanner(f)
	i := 0
	for scanner.Scan() {
		json := scanner.Bytes()
		e, err := ParseJSON(json)
		if err != nil {
			t.Fatalf(err.Error())
		}
		if !reflect.DeepEqual(entries[i], e) {
			t.Fatalf("entry %d parsed from JSON does not match expected value", i)
		}
		i++
	}
}

func TestJSONParseEVEBroken(t *testing.T) {
	f, err := os.Open("testdata/jsonparse_eve_broken1.json")
	if err != nil {
		t.Fatalf(err.Error())
	}
	scanner := bufio.NewScanner(f)
	i := 0
	for scanner.Scan() {
		json := scanner.Bytes()
		e, err := ParseJSON(json)
		if i != 1 {
			if err != nil {
				t.Fatalf(err.Error())
			}
		}
		if i == 1 {
			if err == nil {
				t.Fatalf("broken JSON line should raise an error")
			}
		}
		if i != 1 {
			if !reflect.DeepEqual(entries[i], e) {
				t.Fatalf("entry %d parsed from JSON does not match expected value", i)
			}
		}
		i++
	}
}

func TestJSONParseEVEempty(t *testing.T) {
	f, err := os.Open("testdata/jsonparse_eve_empty.json")
	if err != nil {
		t.Fatalf(err.Error())
	}
	scanner := bufio.NewScanner(f)
	i := 0
	for scanner.Scan() {
		i++
	}
	if i > 0 {
		t.Fatal("empty file should not generate any entries")
	}
}

func TestGetSensorID(t *testing.T) {
	sid, err := GetSensorID()
	if err != nil {
		t.Fatalf(err.Error())
	}
	if len(sid) == 0 {
		t.Fatal("missing sensor ID")
	}
}
