package types

// DCSO FEVER
// Copyright (c) 2017, 2018, DCSO GmbH

import (
	"bytes"
	"net"
	"testing"
)

func TestIPParsing(t *testing.T) {
	ipv4 := "8.8.8.8"
	ipv6 := "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	parsedIPv4, err := parseIP(ipv4)
	if err != nil || !bytes.Equal(parsedIPv4, net.ParseIP(ipv4).To4()) {
		t.Fatal("Conversion failed!")
	}
	parsedIPv6, err := parseIP(ipv6)
	if err != nil || !bytes.Equal(parsedIPv6, net.ParseIP(ipv6)) {
		t.Fatal("Conversion failed!")
	}
}
