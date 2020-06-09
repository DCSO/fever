package util

import (
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func _TestHostNamerQuad8(t *testing.T, ip string) {
	hn := NewHostNamerRDNS(5*time.Second, 5*time.Second)
	v, err := hn.GetHostname(ip)
	if err != nil {
		log.Info(err)
		t.Skip()
	}
	if len(v) == 0 {
		t.Fatal("no response")
	} else {
		log.Infof("got response %v", v)
	}
	v, err = hn.GetHostname(ip)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) == 0 {
		t.Fatal("no response")
	} else {
		log.Infof("got response %v", v)
	}
	time.Sleep(6 * time.Second)
	v, err = hn.GetHostname(ip)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) == 0 {
		t.Fatal("no response")
	} else {
		log.Infof("got response %v", v)
	}
}

func TestHostNamerQuad8v4(t *testing.T) {
	_TestHostNamerQuad8(t, "8.8.8.8")
}

func TestHostNamerQuad8v6(t *testing.T) {
	_TestHostNamerQuad8(t, "2001:4860:4860::8888")
}

func TestHostNamerInvalid(t *testing.T) {
	hn := NewHostNamerRDNS(5*time.Second, 5*time.Second)
	_, err := hn.GetHostname("8.")
	if err == nil {
		t.Fatal("missed error")
	}
}
