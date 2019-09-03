package processing

// DCSO FEVER
// Copyright (c) 2017, 2019, DCSO GmbH

import (
	"bytes"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	log "github.com/sirupsen/logrus"
)

// pDNSReplyDetails holds data for a DNS answer.
type pDNSReplyDetails struct {
	AnsweringHost string `json:"answering_host,omitempty"`
	Rrtype        string `json:"rrtype,omitempty"`
	Rdata         string `json:"rdata,omitempty"`
	Rcode         string `json:"rcode,omitempty"`
	Type          string `json:"type,omitempty"`
	Count         uint64 `json:"count,omitempty"`
}

// pDNSDetails holds summarized stats for a given domain name.
type pDNSDetails struct {
	AnswerSet map[string]*pDNSReplyDetails `json:"-"`
	Details   []pDNSReplyDetails           `json:"rdata,omitempty"`
}
type pDNSEvent struct {
	TimestampFrom time.Time               `json:"timestamp_start"`
	TimestampTo   time.Time               `json:"timestamp_end"`
	DNSDetails    map[string]*pDNSDetails `json:"dns,omitempty"`
	SensorID      string                  `json:"sensor_id,omitempty"`
}

// PDNSCollector extracts and aggregates DNS response data from
// EVE events and sends them to the backend.
type PDNSCollector struct {
	SensorID      string
	Count         int64
	DNSMutex      sync.RWMutex
	DNS           pDNSEvent
	StringBuf     bytes.Buffer
	FlushPeriod   time.Duration
	CloseChan     chan bool
	ClosedChan    chan bool
	Logger        *log.Entry
	Submitter     util.StatsSubmitter
	SubmitChannel chan []byte
}

// MakePDNSCollector creates a new pDNSCollector.
func MakePDNSCollector(flushPeriod time.Duration, submitter util.StatsSubmitter) (*PDNSCollector, error) {
	sensorID, err := util.GetSensorID()
	if err != nil {
		return nil, err
	}
	a := &PDNSCollector{
		FlushPeriod: flushPeriod,
		Logger: log.WithFields(log.Fields{
			"domain": "pdns",
		}),
		DNS: pDNSEvent{
			TimestampFrom: time.Now().UTC(),
			SensorID:      sensorID,
			DNSDetails:    make(map[string]*pDNSDetails),
		},
		CloseChan:     make(chan bool),
		ClosedChan:    make(chan bool),
		SubmitChannel: make(chan []byte, 60),
		Submitter:     submitter,
		SensorID:      sensorID,
	}
	a.SensorID, _ = os.Hostname()
	return a, nil
}

func (a *PDNSCollector) flush() {
	a.DNSMutex.Lock()
	myDNS := a.DNS
	myDNS.TimestampTo = time.Now().UTC()
	a.DNS = pDNSEvent{
		TimestampFrom: time.Now().UTC(),
		SensorID:      a.SensorID,
		DNSDetails:    make(map[string]*pDNSDetails),
	}
	a.Count = 0
	a.DNSMutex.Unlock()
	jsonString, myerror := json.MarshalIndent(myDNS, "", "  ")
	if myerror == nil {
		select {
		case a.SubmitChannel <- jsonString:
			break
		default:
			log.Warning("pDNS channel is full, cannot submit message...")
		}
	} else {
		a.Logger.Warn("error marshaling JSON for passive DNS")
	}

}

func (a *PDNSCollector) countRequestV1(e *types.Entry) {
	a.DNSMutex.Lock()
	a.Count++
	if e.DNSRRName == "" {
		a.DNSMutex.Unlock()
		return
	}
	key := e.DNSRRName
	a.StringBuf.Write([]byte(e.SrcIP))
	a.StringBuf.Write([]byte(e.DNSRRType))
	a.StringBuf.Write([]byte(e.DNSRData))
	a.StringBuf.Write([]byte(e.DNSRCode))
	a.StringBuf.Write([]byte(e.DNSType))
	k := a.StringBuf.String()
	a.StringBuf.Reset()
	if _, ok := a.DNS.DNSDetails[key]; !ok {
		a.DNS.DNSDetails[key] = &pDNSDetails{
			AnswerSet: make(map[string]*pDNSReplyDetails),
			Details: []pDNSReplyDetails{
				pDNSReplyDetails{
					AnsweringHost: e.SrcIP,
					Rrtype:        e.DNSRRType,
					Rdata:         e.DNSRData,
					Rcode:         e.DNSRCode,
					Type:          e.DNSType,
					Count:         1,
				},
			},
		}
		a.DNS.DNSDetails[key].AnswerSet[k] = &a.DNS.DNSDetails[key].Details[0]
	} else {
		as, ok := a.DNS.DNSDetails[key].AnswerSet[k]
		if !ok {
			newDetail := pDNSReplyDetails{
				AnsweringHost: e.SrcIP,
				Rrtype:        e.DNSRRType,
				Rdata:         e.DNSRData,
				Rcode:         e.DNSRCode,
				Type:          e.DNSType,
				Count:         1,
			}
			a.DNS.DNSDetails[key].Details = append(a.DNS.DNSDetails[key].Details, newDetail)
			a.DNS.DNSDetails[key].AnswerSet[k] = &a.DNS.DNSDetails[key].Details[len(a.DNS.DNSDetails[key].AnswerSet)-1]
		} else {
			as.Count++
		}
	}
	a.DNSMutex.Unlock()
}

func (a *PDNSCollector) countRequestV2(e *types.Entry) {
	a.DNSMutex.Lock()
	a.Count++
	if e.DNSRRName == "" || len(e.DNSAnswers) == 0 {
		a.DNSMutex.Unlock()
		return
	}
	for _, v := range e.DNSAnswers {
		key := e.DNSRRName
		a.StringBuf.Write([]byte(e.SrcIP))
		a.StringBuf.Write([]byte(v.DNSRRType))
		a.StringBuf.Write([]byte(v.DNSRData))
		a.StringBuf.Write([]byte(v.DNSRCode))
		a.StringBuf.Write([]byte(v.DNSType))
		k := a.StringBuf.String()
		a.StringBuf.Reset()
		if _, ok := a.DNS.DNSDetails[key]; !ok {
			a.DNS.DNSDetails[key] = &pDNSDetails{
				AnswerSet: make(map[string]*pDNSReplyDetails),
				Details: []pDNSReplyDetails{
					pDNSReplyDetails{
						AnsweringHost: e.SrcIP,
						Rrtype:        v.DNSRRType,
						Rdata:         v.DNSRData,
						Rcode:         v.DNSRCode,
						Type:          v.DNSType,
						Count:         1,
					},
				},
			}
			a.DNS.DNSDetails[key].AnswerSet[k] = &a.DNS.DNSDetails[key].Details[0]
		} else {
			as, ok := a.DNS.DNSDetails[key].AnswerSet[k]
			if !ok {
				newDetail := pDNSReplyDetails{
					AnsweringHost: e.SrcIP,
					Rrtype:        v.DNSRRType,
					Rdata:         v.DNSRData,
					Rcode:         v.DNSRCode,
					Type:          v.DNSType,
					Count:         1,
				}
				a.DNS.DNSDetails[key].Details = append(a.DNS.DNSDetails[key].Details, newDetail)
				a.DNS.DNSDetails[key].AnswerSet[k] = &a.DNS.DNSDetails[key].Details[len(a.DNS.DNSDetails[key].AnswerSet)-1]
			} else {
				as.Count++
			}
		}
	}
	a.DNSMutex.Unlock()
}

// Consume processes an Entry, adding the data within to the internal
// aggregated state
func (a *PDNSCollector) Consume(e *types.Entry) error {
	if e.DNSType == "answer" {
		if e.DNSVersion == 2 {
			a.countRequestV2(e)
		} else {
			a.countRequestV1(e)
		}
	}
	return nil
}

// Run starts the background aggregation service for this handler
func (a *PDNSCollector) Run() {
	go func() {
		for message := range a.SubmitChannel {
			a.Submitter.Submit(message, "pdns", "application/json")
		}
	}()
	go func() {
		i := 0 * time.Second
		for {
			select {
			case <-a.CloseChan:
				close(a.SubmitChannel)
				close(a.ClosedChan)
				return
			default:
				if i >= a.FlushPeriod {
					a.flush()
					i = 0 * time.Second
				}
				time.Sleep(1 * time.Second)
				i += 1 * time.Second
			}
		}
	}()
}

// Stop causes the aggregator to cease aggregating and submitting data
func (a *PDNSCollector) Stop(stopChan chan bool) {
	close(a.CloseChan)
	<-a.ClosedChan
	close(stopChan)
}

// GetName returns the name of the handler
func (a *PDNSCollector) GetName() string {
	return "passive DNS collector"
}

// GetEventTypes returns a slice of event type strings that this handler
// should be applied to
func (a *PDNSCollector) GetEventTypes() []string {
	return []string{"dns"}
}
