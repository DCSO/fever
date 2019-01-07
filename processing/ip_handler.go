package processing

// DCSO FEVER
// Copyright (c) 2018, DCSO GmbH

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	log "github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"
)

// MakeIPAlertEntryForHit returns an alert Entry as raised by an external
// IP hit. The resulting alert will retain
// the triggering event's metadata as well as
// its timestamp.
func MakeIPAlertEntryForHit(e types.Entry, matchedIP string,
	rangerEntry cidranger.RangerEntry, alertPrefix string) types.Entry {
	var eve types.EveEvent
	var newEve types.EveEvent
	var err = json.Unmarshal([]byte(e.JSONLine), &eve)
	if err != nil {
		log.Warn(err, e.JSONLine)
	} else {
		sig := "%s Communication involving IP %s in listed range %s"
		matchedNet := rangerEntry.Network()
		matchedNetString := matchedNet.String()
		newEve = types.EveEvent{
			EventType: "alert",
			Alert: &types.AlertEvent{
				Action:    "allowed",
				Category:  "Potentially Bad Traffic",
				Signature: fmt.Sprintf(sig, alertPrefix, matchedIP, matchedNetString),
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
			Flow:       eve.Flow,
			SMTP:       eve.SMTP,
			SSH:        eve.SSH,
			Email:      eve.Email,
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

// IPHandler is a Handler which is meant to check for the presence of
// event type-specific keywords in a Bloom filter, raising new 'alert' type
// events when matches are found.
type IPHandler struct {
	sync.Mutex
	Logger            *log.Entry
	Name              string
	EventType         string
	Ranger            cidranger.Ranger
	IPListFilename    string
	DatabaseEventChan chan types.Entry
	ForwardHandler    Handler
	DoForwardAlert    bool
	AlertPrefix       string
}

// MakeIPHandler returns a new IPHandler, checking against the given
// IP ranges and sending alerts to databaseChan as well as forwarding them
// to a given forwarding handler.
func MakeIPHandler(ranger cidranger.Ranger,
	databaseChan chan types.Entry, forwardHandler Handler, alertPrefix string) *IPHandler {
	bh := &IPHandler{
		Logger: log.WithFields(log.Fields{
			"domain": "ip-blacklist",
		}),
		Ranger:            ranger,
		DatabaseEventChan: databaseChan,
		ForwardHandler:    forwardHandler,
		DoForwardAlert:    (util.ForwardAllEvents || util.AllowType("alert")),
		AlertPrefix:       alertPrefix,
	}
	log.WithFields(log.Fields{}).Info("IP range list loaded")
	return bh
}

func rangerFromFile(IPListFilename string) (cidranger.Ranger, error) {
	inFile, err := os.Open(IPListFilename)
	if err != nil {
		return nil, err
	}
	defer inFile.Close()
	ranger := cidranger.NewPCTrieRanger()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		lineText := scanner.Text()
		_, network, err := net.ParseCIDR(lineText)
		if err != nil {
			log.Warnf("invalid IP range %s, skipping", lineText)
		} else {
			log.Debugf("adding IP range %s", lineText)
			ranger.Insert(cidranger.NewBasicRangerEntry(*network))
		}
	}
	return ranger, nil
}

// MakeIPHandlerFromFile returns a new IPHandler created from a new
// IP range list specified by the given file name.
func MakeIPHandlerFromFile(IPListFilename string,
	databaseChan chan types.Entry, forwardHandler Handler, alertPrefix string) (*IPHandler, error) {
	ranger, err := rangerFromFile(IPListFilename)
	if err != nil {
		return nil, err
	}
	ih := MakeIPHandler(ranger, databaseChan, forwardHandler, alertPrefix)
	ih.IPListFilename = IPListFilename
	return ih, nil
}

// Reload triggers a reload of the contents of the IP list file.
func (a *IPHandler) Reload() error {
	ranger, err := rangerFromFile(a.IPListFilename)
	if err != nil {
		return err
	}
	a.Lock()
	a.Ranger = ranger
	a.Unlock()
	return nil
}

// Consume processes an Entry, emitting alerts if there is a match
func (a *IPHandler) Consume(e *types.Entry) error {
	a.Lock()
	srcRanges, err := a.Ranger.ContainingNetworks(net.ParseIP(e.SrcIP))
	if err != nil {
		log.Warn(err)
	}
	for _, v := range srcRanges {
		n := MakeIPAlertEntryForHit(*e, e.SrcIP, v, a.AlertPrefix)
		a.DatabaseEventChan <- n
		a.ForwardHandler.Consume(&n)
	}
	dstRanges, err := a.Ranger.ContainingNetworks(net.ParseIP(e.DestIP))
	if err != nil {
		log.Warn(err)
	}
	for _, v := range dstRanges {
		n := MakeIPAlertEntryForHit(*e, e.DestIP, v, a.AlertPrefix)
		a.DatabaseEventChan <- n
		a.ForwardHandler.Consume(&n)
	}
	a.Unlock()
	return nil
}

// GetName returns the name of the handler
func (a *IPHandler) GetName() string {
	return "IP blacklist handler"
}

// GetEventTypes returns a slice of event type strings that this handler
// should be applied to
func (a *IPHandler) GetEventTypes() []string {
	return []string{"http", "dns", "tls", "smtp", "flow", "ssh", "tls", "smb"}
}
