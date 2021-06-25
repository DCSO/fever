package processing

// DCSO FEVER
// Copyright (c) 2018, 2020, DCSO GmbH

import (
	"bufio"
	"net"
	"os"
	"sync"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	log "github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"
)

// IPAlertJSONProviderSrcIP is an AlertJSONProvider for source IP address matches.
type IPAlertJSONProviderSrcIP struct{}

// GetAlertJSON returns the "alert" subobject for an alert EVE event.
func (a IPAlertJSONProviderSrcIP) GetAlertJSON(inputEvent types.Entry,
	prefix string, ioc string) ([]byte, error) {
	return util.GenericGetAlertObjForIoc(inputEvent, prefix, ioc,
		"%s Communication involving IP "+inputEvent.SrcIP+" in listed range %s")
}

// IPAlertJSONProviderDstIP is an AlertJSONProvider for destination IP address
// matches.
type IPAlertJSONProviderDstIP struct{}

// GetAlertJSON returns the "alert" subobject for an alert EVE event.
func (a IPAlertJSONProviderDstIP) GetAlertJSON(inputEvent types.Entry,
	prefix string, ioc string) ([]byte, error) {
	return util.GenericGetAlertObjForIoc(inputEvent, prefix, ioc,
		"%s Communication involving IP "+inputEvent.DestIP+" in listed range %s")
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
	AlertPrefix       string
	Alertifier        *util.Alertifier
}

// MakeIPHandler returns a new IPHandler, checking against the given
// IP ranges and sending alerts to databaseChan as well as forwarding them
// to a given forwarding handler.
func MakeIPHandler(ranger cidranger.Ranger,
	databaseChan chan types.Entry, forwardHandler Handler,
	alertPrefix string) *IPHandler {
	ih := &IPHandler{
		Logger: log.WithFields(log.Fields{
			"domain": "ip-blacklist",
		}),
		Ranger:            ranger,
		DatabaseEventChan: databaseChan,
		ForwardHandler:    forwardHandler,
		AlertPrefix:       alertPrefix,
		Alertifier:        util.MakeAlertifier(alertPrefix),
	}
	ih.Alertifier.SetExtraModifier(bloomExtraModifier)
	ih.Alertifier.RegisterMatchType("ip-src", IPAlertJSONProviderSrcIP{})
	ih.Alertifier.RegisterMatchType("ip-dst", IPAlertJSONProviderDstIP{})
	ih.Alertifier.SetExtraModifier(nil)
	log.WithFields(log.Fields{}).Info("IP range list loaded")
	return ih
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
		matchedNet := v.Network()
		matchedNetString := matchedNet.String()
		if n, err := a.Alertifier.MakeAlert(*e, matchedNetString, "ip-src"); err == nil {
			a.DatabaseEventChan <- *n
			a.ForwardHandler.Consume(n)
		} else {
			log.Warn(err)
		}
	}
	dstRanges, err := a.Ranger.ContainingNetworks(net.ParseIP(e.DestIP))
	if err != nil {
		log.Warn(err)
	}
	for _, v := range dstRanges {
		matchedNet := v.Network()
		matchedNetString := matchedNet.String()
		if n, err := a.Alertifier.MakeAlert(*e, matchedNetString, "ip-dst"); err == nil {
			a.DatabaseEventChan <- *n
			a.ForwardHandler.Consume(n)
		} else {
			log.Warn(err)
		}
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
