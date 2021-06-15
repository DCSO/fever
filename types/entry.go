package types

// DCSO FEVER
// Copyright (c) 2017, 2018, DCSO GmbH

// DNSAnswer is a single DNS answer as observed by Suricata
type DNSAnswer struct {
	DNSRRName string
	DNSRRType string
	DNSRCode  string
	DNSRData  string
	DNSType   string
}

// Entry is a collection of data that needs to be parsed FAST from the entry
type Entry struct {
	SrcIP          string
	SrcHosts       []string
	SrcPort        int64
	DestIP         string
	DestHosts      []string
	DestPort       int64
	Timestamp      string
	EventType      string
	Proto          string
	HTTPHost       string
	HTTPUrl        string
	HTTPMethod     string
	JSONLine       string
	DNSVersion     int64
	DNSRRName      string
	DNSRRType      string
	DNSRCode       string
	DNSRData       string
	DNSType        string
	DNSAnswers     []DNSAnswer
	TLSSNI         string
	BytesToClient  int64
	BytesToServer  int64
	PktsToClient   int64
	PktsToServer   int64
	FlowID         string
	Iface          string
	AppProto       string
	TLSFingerprint string
}
