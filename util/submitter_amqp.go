package util

// DCSO FEVER
// Copyright (c) 2017, 2018, DCSO GmbH

import (
	"bytes"
	"compress/gzip"
	"sync"
	"time"

	"github.com/NeowayLabs/wabbit"
	"github.com/NeowayLabs/wabbit/amqp"
	log "github.com/sirupsen/logrus"
	origamqp "github.com/streadway/amqp"
)

// AMQPSubmitter is a StatsSubmitter that sends reports to a RabbitMQ exchange.
type AMQPSubmitter struct {
	URL              string
	Verbose          bool
	SensorID         string
	Target           string
	Conn             wabbit.Conn
	Channel          wabbit.Channel
	StopReconnection chan bool
	ErrorChan        chan wabbit.Error
	Logger           *log.Entry
	Compress         bool
	ChanMutex        sync.Mutex
	ConnMutex        sync.Mutex
	Reconnector      func(string) (wabbit.Conn, string, error)
}

const (
	amqpReconnDelay = 2 * time.Second
)

func defaultReconnector(amqpURI string) (wabbit.Conn, string, error) {
	conn, err := amqp.Dial(amqpURI)
	if err != nil {
		return nil, "fanout", err
	}
	return conn, "fanout", err
}

func reconnectOnFailure(s *AMQPSubmitter) {
	for {
		select {
		case <-s.StopReconnection:
			return
		case rabbitErr := <-s.ErrorChan:
			if rabbitErr != nil {
				log.Warnf("RabbitMQ connection failed: %s", rabbitErr.Reason())
				s.ChanMutex.Lock()
				for {
					time.Sleep(amqpReconnDelay)
					connErr := s.connect()
					if connErr != nil {
						log.Warnf("RabbitMQ error: %s", connErr)
					} else {
						log.Infof("Reestablished connection to %s", s.URL)
						s.Conn.NotifyClose(s.ErrorChan)
						break
					}
				}
				s.ChanMutex.Unlock()
			}
		}
	}
}

func (s *AMQPSubmitter) connect() error {
	var err error
	var exchangeType string

	s.ConnMutex.Lock()
	s.Conn, exchangeType, err = s.Reconnector(s.URL)
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
	// We do not want to declare an exchange on non-default connection methods,
	// as they may not support all exchange types. For instance amqptest does
	// not support 'fanout'.
	err = s.Channel.ExchangeDeclare(
		s.Target,     // name
		exchangeType, // type
		wabbit.Option{
			"durable":    true,
			"autoDelete": false,
			"internal":   false,
			"noWait":     false,
		},
	)
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
	reconnector func(string) (wabbit.Conn, string, error)) (*AMQPSubmitter, error) {
	var err error
	mySubmitter := &AMQPSubmitter{
		URL:              url,
		Target:           target,
		Verbose:          verbose,
		ErrorChan:        make(chan wabbit.Error),
		Reconnector:      reconnector,
		Compress:         false,
		StopReconnection: make(chan bool),
	}
	mySubmitter.Logger = log.WithFields(log.Fields{
		"domain":    "submitter",
		"submitter": "AMQP",
	})
	mySubmitter.SensorID, err = GetSensorID()
	if err != nil {
		return nil, err
	}
	err = mySubmitter.connect()
	if err != nil {
		return nil, err
	}
	mySubmitter.Conn.NotifyClose(mySubmitter.ErrorChan)

	go reconnectOnFailure(mySubmitter)

	return mySubmitter, nil
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
			"sensor_id":  s.SensorID,
			"compressed": isCompressed,
		},
	}
	for k, v := range myHeaders {
		option["headers"].(origamqp.Table)[k] = v
	}

	err := s.Channel.Publish(
		s.Target, // exchange
		key,      // routing key
		payload,
		option)
	if err != nil {
		s.Logger.Warn(err)
	} else {
		s.Logger.WithFields(log.Fields{
			"rawsize":     len(rawData),
			"payloadsize": len(payload),
		}).Infof("submission to %s (%s) successful", s.Target, key)
	}
}

// Finish cleans up the AMQP connection.
func (s *AMQPSubmitter) Finish() {
	close(s.StopReconnection)
	if s.Verbose {
		s.Logger.Info("closing connection")
	}
	if s.Channel != nil {
		s.Channel.Close()
	}
	s.ConnMutex.Lock()
	if s.Conn != nil {
		s.Conn.Close()
	}
	s.ConnMutex.Unlock()
}
