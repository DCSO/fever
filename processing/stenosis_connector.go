package processing

// DCSO FEVER
// Copyright (c) 2020, DCSO GmbH

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/DCSO/fever/stenosis/api"
	"github.com/DCSO/fever/stenosis/task"
	"github.com/DCSO/fever/types"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	cache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

const (
	defaultStenosisTimeBracket = 1 * time.Minute
	maxErrorCount              = 10
)

// StenosisConnector is a handler that caches alerts and waits for the
// associated flow to finish, then annotates all alerts with flow IDs and
// performs queries against a specified Stenosis server. Alerts will then
// be annotated with returned tokens and forwarded.
type StenosisConnector struct {
	Endpoint       string
	Client         api.StenosisServiceQueryClient
	TimeBracket    time.Duration
	Timeout        time.Duration
	ErrorCount     uint64
	FlowNotifyChan chan types.Entry
	Cache          *cache.Cache
}

// MakeStenosisConnector returns a new StenosisConnector for the
// given parameters.
func MakeStenosisConnector(endpoint string, timeout, timeBracket time.Duration,
	notifyChan chan types.Entry, forwardChan chan []byte, alertCacheExpiry time.Duration,
	tlsConfig *tls.Config) (*StenosisConnector, error) {
	sConn := &StenosisConnector{
		Endpoint:       endpoint,
		FlowNotifyChan: notifyChan,
		TimeBracket: func() time.Duration {
			if timeBracket != 0 {
				return timeBracket
			}
			return defaultStenosisTimeBracket
		}(),
		Timeout: timeout,
		Cache:   cache.New(alertCacheExpiry, 30*time.Second),
	}
	dialOpts := make([]grpc.DialOption, 0, 1)
	if tlsConfig != nil {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		dialOpts = append(dialOpts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(endpoint, dialOpts...)
	if err != nil {
		return nil, err
	}
	sConn.Client = api.NewStenosisServiceQueryClient(conn)

	go func() {
		defer conn.Close()

		for flow := range sConn.FlowNotifyChan {
			var myAlerts []types.Entry
			aval, exist := sConn.Cache.Get(flow.FlowID)
			if exist {
				log.Debugf("flow with existing alert finished: %v", flow)
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
							jsonCopy, err = json.Marshal(ev)
							if err != nil {
								log.Error(err)
								continue
							}
							forwardChan <- jsonCopy
						}
					}
				}
				sConn.Cache.Delete(flow.FlowID)
			}
		}
	}()
	return sConn, nil
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
	if err := json.Unmarshal([]byte(e.JSONLine), &ev); err != nil {
		return nil, err
	}
	log.Debug(string(e.JSONLine))

	query := &task.Query{
		Type: task.QueryType_FLOW_PARAM,
		Content: &task.Query_FlowParam{FlowParam: &task.FlowParam{
			Network:     strings.ToLower(ev.Proto),
			SrcHostPort: fmt.Sprintf("%s:%d", ev.SrcIP, ev.SrcPort),
			DstHostPort: fmt.Sprintf("%s:%d", ev.DestIP, ev.DestPort),
		}},
	}
	if ev.Flow != nil && ev.Flow.Start != nil {
		query.AfterTime, _ = ptypes.TimestampProto(ev.Flow.Start.Time.Add(-s.TimeBracket))
	}
	if ev.Flow != nil && ev.Flow.End != nil {
		query.BeforeTime, _ = ptypes.TimestampProto(ev.Flow.End.Time.Add(s.TimeBracket))
	}
	// prepare context
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	nowTime := time.Now()
	resp, err := s.Client.Query(ctx, query)
	if err != nil {
		return nil, s.handleError(fmt.Errorf("error submitting entry to stenosis: %s", err.Error()))
	}
	log.Debugf("query took %v", time.Since(nowTime))
	s.resetErrors()

	return resp, nil
}
