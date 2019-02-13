package util

// Parts of this code have been taken from
// https://github.com/streadway/amqp/blob/master/_examples/simple-consumer/consumer.go
// released under the license of the main streadway/amqp project:
//
// Copyright (c) 2012, Sean Treadway, SoundCloud Ltd.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// Redistributions in binary form must reproduce the above copyright notice, this
// list of conditions and the following disclaimer in the documentation and/or
// other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import (
	"fmt"

	"github.com/NeowayLabs/wabbit"
	"github.com/NeowayLabs/wabbit/amqptest"
	log "github.com/sirupsen/logrus"
)

// Consumer reads and processes messages from a fake RabbitMQ server.
type Consumer struct {
	conn     wabbit.Conn
	channel  wabbit.Channel
	tag      string
	done     chan error
	Callback func(wabbit.Delivery)
}

// NewConsumer creates a new consumer with the given properties. The callback
// function is called for each delivery accepted from a consumer channel.
func NewConsumer(amqpURI, exchange, exchangeType, queueName, key, ctag string, callback func(wabbit.Delivery)) (*Consumer, error) {
	var err error
	c := &Consumer{
		conn:     nil,
		channel:  nil,
		tag:      ctag,
		done:     make(chan error),
		Callback: callback,
	}

	log.Debugf("dialing %q", amqpURI)
	c.conn, err = amqptest.Dial(amqpURI)
	if err != nil {
		return nil, fmt.Errorf("dial: %s", err)
	}

	log.Debugf("got Connection, getting Channel")
	c.channel, err = c.conn.Channel()
	if err != nil {
		return nil, fmt.Errorf("channel: %s", err)
	}

	log.Debugf("got Channel, declaring Exchange (%q)", exchange)
	if err = c.channel.ExchangeDeclare(
		exchange,     // name of the exchange
		exchangeType, // type
		wabbit.Option{
			"durable":  true,
			"delete":   false,
			"internal": false,
			"noWait":   false,
		},
	); err != nil {
		return nil, fmt.Errorf("exchange declare: %s", err)
	}

	queue, err := c.channel.QueueDeclare(
		queueName, // name of the queue
		wabbit.Option{
			"durable":   true,
			"delete":    false,
			"exclusive": false,
			"noWait":    false,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("queue declare: %s", err)
	}

	log.Debugf("declared Queue (%q %d messages, %d consumers), binding to Exchange (key %q)",
		queue.Name(), queue.Messages(), queue.Consumers(), key)

	if err = c.channel.QueueBind(
		queue.Name(), // name of the queue
		key,          // bindingKey
		exchange,     // sourceExchange
		wabbit.Option{
			"noWait": false,
		},
	); err != nil {
		return nil, fmt.Errorf("queue bind: %s", err)
	}

	log.Debugf("Queue bound to Exchange, starting Consume (consumer tag %q)", c.tag)
	deliveries, err := c.channel.Consume(
		queue.Name(), // name
		c.tag,        // consumerTag,
		wabbit.Option{
			"exclusive": false,
			"noLocal":   false,
			"noWait":    false,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("queue consume: %s", err)
	}
	go handle(deliveries, c.done, c.Callback)

	return c, nil
}

// Shutdown shuts down a consumer, closing down its channels and connections.
func (c *Consumer) Shutdown() error {
	// will close() the deliveries channel
	if err := c.channel.Close(); err != nil {
		return fmt.Errorf("channel close failed: %s", err)
	}
	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("AMQP connection close error: %s", err)
	}
	defer log.Debugf("AMQP shutdown OK")
	// wait for handle() to exit
	return <-c.done
}

func handle(deliveries <-chan wabbit.Delivery, done chan error, callback func(wabbit.Delivery)) {
	for d := range deliveries {
		log.Debugf(
			"got %dB delivery: [%v] %q",
			len(d.Body()),
			d.DeliveryTag(),
			d.Body(),
		)
		callback(d)
		d.Ack(false)
	}
	done <- nil
}
