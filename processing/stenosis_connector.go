package processing

// DCSO FEVER
// Copyright (c) 2020, DCSO GmbH

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/DCSO/fever/types"

	cache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

const (
	defaultStenosisTimeBracket = 1 * time.Second
	maxErrorCount              = 10
)

// StenosisConnector is a handler that caches alerts and waits for the
// associated flow to finish, then annotates all alerts with flow IDs and
// performs queries against a specified Stenosis server. Alerts will then
// be annotated with returned tokens and forwarded.
type StenosisConnector struct {
	Endpoint       string
	Client         http.Client
	TimeBracket    time.Duration
	ErrorCount     uint64
	FlowNotifyChan chan types.Entry
	Cache          *cache.Cache
}

// StenosisFlowParam contains all data required for a FLOW_PARAM type request.
type StenosisFlowParam struct {
	Network     string `json:"network"`
	SrcHostPort string `json:"src_host_port"`
	DstHostPort string `json:"dst_host_port"`
}

// StenosisRequest contains all data required to do a request against a
// Stenosis server.
type StenosisRequest struct {
	Type       string            `json:"type"`
	FlowParam  StenosisFlowParam `json:"flow_param"`
	AfterTime  string            `json:"after_time,omitempty"`
	BeforeTime string            `json:"before_time,omitempty"`
}

// MakeStenosisConnector returns a new StenosisConnector for the
// given parameters.
func MakeStenosisConnector(endpoint string, timeout time.Duration,
	notifyChan chan types.Entry, forwardChan chan []byte,
	tlsConfig *tls.Config) *StenosisConnector {
	sConn := &StenosisConnector{
		Endpoint: endpoint,
		Client: http.Client{
			Timeout: timeout,
		},
		FlowNotifyChan: notifyChan,
		TimeBracket:    defaultStenosisTimeBracket,
		//TODO: make configurable
		Cache: cache.New(30*time.Minute, 30*time.Second),
	}
	if tlsConfig != nil {
		sConn.Client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	go func() {
		for flow := range sConn.FlowNotifyChan {
			var myAlerts []types.Entry
			aval, exist := sConn.Cache.Get(flow.FlowID)
			if exist {
				log.Debugf("flow with existing alert finished: %f", flow)
				myAlerts = aval.([]types.Entry)
				outParsed, err := sConn.submit(&flow)
				if err != nil {
					log.Error(err)
					for _, a := range myAlerts {
						forwardChan <- []byte(a.JSONLine)
					}
				} else {
					if forwardChan != nil {
						for _, a := range myAlerts {
							var ev types.EveOutEvent
							// annotate alerts with flows and forward
							err := json.Unmarshal([]byte(a.JSONLine), &ev)
							if err != nil {
								log.Error(err)
							}
							if ev.ExtraInfo == nil {
								ev.ExtraInfo = &types.ExtraInfo{
									StenosisInfo: outParsed,
								}
							} else {
								ev.ExtraInfo.StenosisInfo = outParsed
							}
							var jsonCopy []byte
							jsonCopy, _ = json.Marshal(ev)
							forwardChan <- jsonCopy
						}
					}
				}
				sConn.Cache.Delete(flow.FlowID)
			}
		}
	}()
	return sConn
}

func (s *StenosisConnector) formatQuery(e types.EveOutEvent) ([]byte, error) {
	request := StenosisRequest{
		Type: "FLOW_PARAM", // hardcoded for now
		FlowParam: StenosisFlowParam{
			Network:     strings.ToLower(e.Proto),
			SrcHostPort: fmt.Sprintf("%s:%d", e.SrcIP, e.SrcPort),
			DstHostPort: fmt.Sprintf("%s:%d", e.DestIP, e.DestPort),
		},
	}
	if e.Flow != nil && e.Flow.Start != nil {
		request.AfterTime = e.Flow.Start.Time.Add(-s.TimeBracket).Format(time.RFC3339Nano)
	}
	if e.Flow != nil && e.Flow.End != nil {
		request.BeforeTime = e.Flow.End.Time.Add(s.TimeBracket).Format(time.RFC3339Nano)
	}
	json, err := json.Marshal(request)
	return json, err
}

func (s *StenosisConnector) handleError(err error) error {
	s.ErrorCount++
	if s.ErrorCount == maxErrorCount {
		log.Warning("maximum reported error count exceeded, disabling output")
		return nil
	} else if s.ErrorCount > maxErrorCount {
		return nil
	} else {
		return err
	}
}

func (s *StenosisConnector) resetErrors() {
	if s.ErrorCount > maxErrorCount {
		log.Warning("re-enabling error reporting")
	}
	s.ErrorCount = 0
}

// Accept registers the given Entry into the connector's cache setup.
func (s *StenosisConnector) Accept(e *types.Entry) {
	var myAlerts []types.Entry
	aval, exist := s.Cache.Get(e.FlowID)
	if exist {
		myAlerts = aval.([]types.Entry)
	} else {
		myAlerts = make([]types.Entry, 0)
	}
	myAlerts = append(myAlerts, *e)
	s.Cache.Set(e.FlowID, myAlerts, cache.DefaultExpiration)
}

func (s *StenosisConnector) submit(e *types.Entry) (interface{}, error) {
	var ev types.EveOutEvent
	err := json.Unmarshal([]byte(e.JSONLine), &ev)
	if err != nil {
		return nil, err
	}
	log.Debug(string(e.JSONLine))
	jsonRequest, err := s.formatQuery(ev)
	if err != nil {
		return nil, err
	}
	log.Debug(string(jsonRequest))

	// prepare context
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, s.Client.Timeout)
	defer cancel()

	nowTime := time.Now()

	// prepare request
	req, _ := http.NewRequest(http.MethodPost, s.Endpoint, bytes.NewBuffer(jsonRequest))
	req = req.WithContext(ctx)
	req.Header = map[string][]string{
		"Content-Type": {"application/json"},
	}

	// get response
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, s.handleError(fmt.Errorf("error submitting entry to stenosis: %s", err.Error()))
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, s.handleError(fmt.Errorf("error submitting entry to stenosis: %s", resp.Status))
	}

	responseBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	log.Debugf("query took %f", time.Since(nowTime))

	if err != nil {
		return nil, s.handleError(err)
	}

	// parse and attach response
	var outParsed interface{}
	err = json.Unmarshal(responseBytes, &outParsed)
	if err != nil {
		return nil, s.handleError(err)
	}

	s.resetErrors()

	return outParsed, nil
}
