package util

import (
	"testing"
	"time"
)

func TestHostNamerQuad8(t *testing.T) {
	hn := NewHostNamer(5*time.Second, 5*time.Second)
	v, err := hn.GetHostname("8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if len(v) == 0 {
		t.Fatal("no response")
	}
	v, err = hn.GetHostname("8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if len(v) == 0 {
		t.Fatal("no response")
	}
	time.Sleep(6 * time.Second)
	v, err = hn.GetHostname("8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if len(v) == 0 {
		t.Fatal("no response")
	}
}

func TestHostNamerInvalid(t *testing.T) {
	hn := NewHostNamer(5*time.Second, 5*time.Second)
	_, err := hn.GetHostname("8.")
	if err == nil {
		t.Fatal("missed error")
	}
}
