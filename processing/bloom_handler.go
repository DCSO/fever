package processing

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	"github.com/DCSO/bloom"
	log "github.com/sirupsen/logrus"
)

var sigs = map[string]string{
	"http-url":  "%s Possibly bad HTTP URL: ",
	"http-host": "%s Possibly bad HTTP host: ",
	"tls-sni":   "%s Possibly bad TLS SNI: ",
	"dns":       "%s Possibly bad DNS lookup to ",
}

// MakeAlertEntryForHit returns an alert Entry as raised by an external
// indicator match, e.g. a Bloom filter hit. The resulting alert will retain
// the triggering event's metadata (e.g. 'dns' or 'http' objects) as well as
// its timestamp.
func MakeAlertEntryForHit(e types.Entry, eType string, alertPrefix string) types.Entry {
	var eve types.EveEvent
	var newEve types.EveEvent
	var err = json.Unmarshal([]byte(e.JSONLine), &eve)
	if err != nil {
		log.Warn(err, e.JSONLine)
	} else {
		var value string
		if eType == "http-url" {
			value = fmt.Sprintf("%s | %s | %s", e.HTTPMethod, e.HTTPHost, e.HTTPUrl)
		} else if eType == "http-host" {
			value = e.HTTPHost
		} else if eType == "dns" {
			value = e.DNSRRName
		} else if eType == "tls-sni" {
			value = e.TLSSni
		}
		var sig = "%s Possibly bad traffic: "
		if v, ok := sigs[eType]; ok {
			sig = v
		}
		newEve = types.EveEvent{
			EventType: "alert",
			Alert: &types.AlertEvent{
				Action:    "allowed",
				Category:  "Potentially Bad Traffic",
				Signature: fmt.Sprintf(sig, alertPrefix) + value,
			},
			Stream:     eve.Stream,
			InIface:    eve.InIface,
			SrcIP:      eve.SrcIP,
			SrcPort:    eve.SrcPort,
			DestIP:     eve.DestIP,
			DestPort:   eve.DestPort,
			Proto:      eve.Proto,
			TxID:       eve.TxID,
			Timestamp:  eve.Timestamp,
			PacketInfo: eve.PacketInfo,
			HTTP:       eve.HTTP,
			DNS:        eve.DNS,
			TLS:        eve.TLS,
		}
	}
	newEntry := e
	json, err := json.Marshal(newEve)
	if err != nil {
		log.Warn(err)
	} else {
		newEntry.JSONLine = string(json)
	}
	newEntry.EventType = "alert"

	return newEntry
}

// BloomHandler is a Handler which is meant to check for the presence of
// event type-specific keywords in a Bloom filter, raising new 'alert' type
// events when matches are found.
type BloomHandler struct {
	sync.Mutex
	Logger                *log.Entry
	Name                  string
	EventType             string
	IocBloom              *bloom.BloomFilter
	BloomFilename         string
	BloomFileIsCompressed bool
	DatabaseEventChan     chan types.Entry
	ForwardHandler        Handler
	DoForwardAlert        bool
	AlertPrefix           string
}

// BloomNoFileErr is an error thrown when a file-based operation (e.g.
// reloading) is  attempted on a bloom filter object with no file information
// attached.
type BloomNoFileErr struct {
	s string
}

// Error returns the error message.
func (e *BloomNoFileErr) Error() string {
	return e.s
}

// MakeBloomHandler returns a new BloomHandler, checking against the given
// Bloom filter and sending alerts to databaseChan as well as forwarding them
// to a given forwarding handler.
func MakeBloomHandler(iocBloom *bloom.BloomFilter,
	databaseChan chan types.Entry, forwardHandler Handler, alertPrefix string) *BloomHandler {
	bh := &BloomHandler{
		Logger: log.WithFields(log.Fields{
			"domain": "bloom",
		}),
		IocBloom:          iocBloom,
		DatabaseEventChan: databaseChan,
		ForwardHandler:    forwardHandler,
		DoForwardAlert:    (util.ForwardAllEvents || util.AllowType("alert")),
		AlertPrefix:       alertPrefix,
	}
	log.WithFields(log.Fields{
		"N": iocBloom.N,
	}).Info("Bloom filter loaded")
	return bh
}

// MakeBloomHandlerFromFile returns a new BloomHandler created from a new
// Bloom filter specified by the given file name.
func MakeBloomHandlerFromFile(bloomFilename string, compressed bool,
	databaseChan chan types.Entry, forwardHandler Handler, alertPrefix string) (*BloomHandler, error) {
	iocBloom, err := bloom.LoadFilter(bloomFilename, compressed)
	if err != nil {
		if err == io.EOF {
			log.Warnf("file is empty, using empty default one")
			myBloom := bloom.Initialize(100, 0.00000001)
			iocBloom = &myBloom
		} else if strings.Contains(err.Error(), "value of k (number of hash functions) is too high") {
			log.Warnf("malformed Bloom filter file, using empty default one")
			myBloom := bloom.Initialize(100, 0.00000001)
			iocBloom = &myBloom
		} else {
			return nil, err
		}
	}
	bh := MakeBloomHandler(iocBloom, databaseChan, forwardHandler, alertPrefix)
	bh.BloomFilename = bloomFilename
	bh.BloomFileIsCompressed = compressed
	return bh, nil
}

// Reload triggers a reload of the contents of the file with the name.
func (a *BloomHandler) Reload() error {
	if a.BloomFilename == "" {
		return &BloomNoFileErr{"BloomHandler was not created from a file, no reloading possible"}
	}
	iocBloom, err := bloom.LoadFilter(a.BloomFilename, a.BloomFileIsCompressed)
	if err != nil {
		if err == io.EOF {
			log.Warnf("file is empty, using empty default one")
			myBloom := bloom.Initialize(100, 0.00000001)
			iocBloom = &myBloom
		} else if strings.Contains(err.Error(), "value of k (number of hash functions) is too high") {
			log.Warnf("malformed Bloom filter file, using empty default one")
			myBloom := bloom.Initialize(100, 0.00000001)
			iocBloom = &myBloom
		} else {
			return err
		}
	}
	a.Lock()
	a.IocBloom = iocBloom
	a.Unlock()
	log.WithFields(log.Fields{
		"N": iocBloom.N,
	}).Info("Bloom filter reloaded")
	return nil
}

// Consume processes an Entry, emitting alerts if there is a match
func (a *BloomHandler) Consume(e *types.Entry) error {
	if e.EventType == "http" {
		var checkStr string
		a.Lock()
		if strings.Contains(e.HTTPUrl, "://") {
			checkStr = e.HTTPUrl
		} else {
			checkStr = "http://" + e.HTTPHost + e.HTTPUrl
		}
		if a.IocBloom.Check([]byte(checkStr)) {
			n := MakeAlertEntryForHit(*e, "http-url", a.AlertPrefix)
			a.DatabaseEventChan <- n
			a.ForwardHandler.Consume(&n)
		}
		if a.IocBloom.Check([]byte(e.HTTPHost)) {
			n := MakeAlertEntryForHit(*e, "http-host", a.AlertPrefix)
			a.DatabaseEventChan <- n
			a.ForwardHandler.Consume(&n)
		}
		a.Unlock()
	}
	if e.EventType == "dns" {
		a.Lock()
		if a.IocBloom.Check([]byte(e.DNSRRName)) {
			n := MakeAlertEntryForHit(*e, "dns", a.AlertPrefix)
			a.DatabaseEventChan <- n
			a.ForwardHandler.Consume(&n)
		}
		a.Unlock()
	}
	if e.EventType == "tls" {
		a.Lock()
		if a.IocBloom.Check([]byte(e.TLSSni)) {
			n := MakeAlertEntryForHit(*e, "tls-sni", a.AlertPrefix)
			a.DatabaseEventChan <- n
			a.ForwardHandler.Consume(&n)
		}
		a.Unlock()
	}
	return nil
}

// GetName returns the name of the handler
func (a *BloomHandler) GetName() string {
	return "Bloom filter handler"
}

// GetEventTypes returns a slice of event type strings that this handler
// should be applied to
func (a *BloomHandler) GetEventTypes() []string {
	return []string{"http", "dns", "tls"}
}
