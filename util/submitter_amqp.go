package util

// DCSO FEVER
// Copyright (c) 2017, 2021, DCSO GmbH

import (
	"bytes"
	"compress/gzip"
	"sync"
	"time"

	"github.com/NeowayLabs/wabbit"
	"github.com/NeowayLabs/wabbit/amqp"
	"github.com/NeowayLabs/wabbit/utils"
	origamqp "github.com/rabbitmq/amqp091-go"
	log "github.com/sirupsen/logrus"
)

// AMQPBaseSubmitter is the base engine that sends reports to a RabbitMQ host and
// handles reconnection.
type AMQPBaseSubmitter struct {
	URL              string
	Verbose          bool
	SensorID         string
	Conn             wabbit.Conn
	Channel          wabbit.Channel
	StopReconnection chan bool
	ErrorChan        chan wabbit.Error
	Logger           *log.Entry
	ChanMutex        sync.Mutex
	ConnMutex        sync.Mutex
	Reconnector      func(string) (wabbit.Conn, error)
	NofSubmitters    uint
}

// AMQPSubmitter is a StatsSubmitter that sends reports to a RabbitMQ exchange.
type AMQPSubmitter struct {
	Submitter *AMQPBaseSubmitter
	Target    string
	Compress  bool
}

const (
	amqpReconnDelay = 5 * time.Second
)

var (
	gSubmitters = make(map[string]*AMQPBaseSubmitter)
)

func defaultReconnector(amqpURI string) (wabbit.Conn, error) {
	conn, err := amqp.Dial(amqpURI)
	if err != nil {
		return nil, err
	}
	return conn, err
}

func reconnectOnFailure(s *AMQPBaseSubmitter) {
	errChan := s.ErrorChan
	for {
		select {
		case <-s.StopReconnection:
			return
		case rabbitErr := <-errChan:
			if rabbitErr != nil {
				log.Warnf("RabbitMQ connection failed: %s", rabbitErr.Reason())
				s.ChanMutex.Lock()
				for {
					connErr := s.connect()
					if connErr != nil {
						log.Warnf("RabbitMQ error: %s", connErr)
					} else {
						log.Infof("Reestablished connection to %s", s.URL)
						errChan = make(chan wabbit.Error)
						s.Conn.NotifyClose(errChan)
						s.ErrorChan = errChan
						break
					}
					time.Sleep(amqpReconnDelay)
				}
				s.ChanMutex.Unlock()
			}
		}
	}
}

func (s *AMQPBaseSubmitter) connect() error {
	var err error

	s.ConnMutex.Lock()
	s.Logger.Debugf("calling reconnector")
	s.Conn, err = s.Reconnector(s.URL)
	if err != nil {
		s.Conn = nil
		s.ConnMutex.Unlock()
		return err
	}
	s.Channel, err = s.Conn.Channel()
	if err != nil {
		s.Conn.Close()
		s.ConnMutex.Unlock()
		return err
	}
	log.Debugf("Submitter established connection to %s", s.URL)
	s.ConnMutex.Unlock()

	return nil
}

// MakeAMQPSubmitterWithReconnector creates a new submitter connected to a
// RabbitMQ server at the given URL, using the reconnector function as a means
// to Dial() in order to obtain a Connection object.
func MakeAMQPSubmitterWithReconnector(url string, target string, verbose bool,
	reconnector func(string) (wabbit.Conn, error)) (*AMQPSubmitter, error) {
	var err error
	var mySubmitter *AMQPBaseSubmitter
	if _, ok := gSubmitters[url]; !ok {

		mySubmitter = &AMQPBaseSubmitter{
			URL:              url,
			Verbose:          verbose,
			ErrorChan:        make(chan wabbit.Error),
			Reconnector:      reconnector,
			StopReconnection: make(chan bool),
		}
		mySubmitter.Logger = log.WithFields(log.Fields{
			"domain":    "submitter",
			"submitter": "AMQP",
			"url":       url,
		})
		mySubmitter.Logger.Debugf("new base submitter created")
		mySubmitter.SensorID, err = GetSensorID()
		if err != nil {
			return nil, err
		}

		// Start reconnect loop in separate goroutine.
		go reconnectOnFailure(mySubmitter)
		// The reconnect loop started in the line above will only trigger when
		// something is received on the error channel. We'll emit a fake error
		// to trigger the initial connect to avoid code duplication.
		mySubmitter.ErrorChan <- utils.NewError(0, "Initial connect", true, true)

		gSubmitters[url] = mySubmitter
		mySubmitter.NofSubmitters++
		mySubmitter.Logger.Debugf("number of submitters now %d", mySubmitter.NofSubmitters)
	} else {
		mySubmitter = gSubmitters[url]
	}
	retSubmitter := &AMQPSubmitter{
		Submitter: mySubmitter,
		Target:    target,
	}
	return retSubmitter, nil
}

// MakeAMQPSubmitter creates a new submitter connected to a RabbitMQ server
// at the given URL.
func MakeAMQPSubmitter(url string, target string, verbose bool) (*AMQPSubmitter, error) {
	return MakeAMQPSubmitterWithReconnector(url, target, verbose, defaultReconnector)
}

// UseCompression enables gzip compression of submitted payloads.
func (s *AMQPSubmitter) UseCompression() {
	s.Compress = true
}

// Submit sends the rawData payload via the registered RabbitMQ connection.
func (s *AMQPSubmitter) Submit(rawData []byte, key string, contentType string) {
	s.SubmitWithHeaders(rawData, key, contentType, nil)
}

// SubmitWithHeaders sends the rawData payload via the registered RabbitMQ connection,
// adding some extra key-value pairs to the header.
func (s *AMQPSubmitter) SubmitWithHeaders(rawData []byte, key string, contentType string, myHeaders map[string]string) {
	var payload []byte
	var encoding string
	var isCompressed string
	defer s.Submitter.ConnMutex.Unlock()

	if s.Compress {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		w.Write(rawData)
		w.Close()
		payload = b.Bytes()
		isCompressed = "true"
		encoding = "gzip"
	} else {
		payload = rawData
		isCompressed = "false"
	}

	option := wabbit.Option{
		"contentType":     contentType,
		"contentEncoding": encoding,
		"headers": origamqp.Table{
			"sensor_id":  s.Submitter.SensorID,
			"compressed": isCompressed,
		},
	}
	for k, v := range myHeaders {
		option["headers"].(origamqp.Table)[k] = v
	}

	s.Submitter.ConnMutex.Lock()
	// Double-check whether a value is nil and make sure we won't deref it.
	switch {
	case s.Submitter == nil:
		s.Submitter.Logger.Errorf("submitter was nil, skipping submission for %s",
			s.Target)
		return
	case s.Submitter.Channel == nil:
		s.Submitter.Logger.Errorf("channel was nil, skipping submission for %s/%s",
			s.Submitter.URL, s.Target)
		return
	}
	err := s.Submitter.Channel.Publish(
		s.Target, // exchange
		key,      // routing key
		payload,
		option)
	if err != nil {
		s.Submitter.Logger.Warn(err)
	} else {
		s.Submitter.Logger.WithFields(log.Fields{
			"rawsize":     len(rawData),
			"payloadsize": len(payload),
		}).Debugf("submission to %s:%s (%s) successful", s.Submitter.URL, s.Target, key)
	}
}

// Finish cleans up the AMQP connection (reference counted).
func (s *AMQPSubmitter) Finish() {
	s.Submitter.Logger.Debugf("finishing submitter %s (%s)", s.Submitter.URL, s.Target)
	if s.Submitter.NofSubmitters == 1 {
		close(s.Submitter.StopReconnection)
		if s.Submitter.Verbose {
			s.Submitter.Logger.Info("closing connection")
		}
		if s.Submitter.Channel != nil {
			s.Submitter.Channel.Close()
		}
		s.Submitter.ConnMutex.Lock()
		if s.Submitter.Conn != nil {
			s.Submitter.Conn.Close()
		}
		s.Submitter.ConnMutex.Unlock()
		delete(gSubmitters, s.Submitter.URL)
	} else {
		s.Submitter.NofSubmitters--
		s.Submitter.Logger.Debugf("number of submitters now %d", s.Submitter.NofSubmitters)
	}
}
