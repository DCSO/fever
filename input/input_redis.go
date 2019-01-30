package input

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

import (
	"io"
	"sync"
	"time"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	"github.com/garyburd/redigo/redis"
	log "github.com/sirupsen/logrus"
)

var cnt, lastcnt uint64
var perfStatsSendInterval = 10 * time.Second
var backOffTime = 500 * time.Millisecond

// RedisInputPerfStats contains performance stats written to InfluxDB
// for monitoring.
type RedisInputPerfStats struct {
	RedisQueueLength uint64 `influx:"redis_queue_length"`
}

// RedisInput is an Input reading JSON EVE input from Redis list.
type RedisInput struct {
	EventChan     chan types.Entry
	Verbose       bool
	Running       bool
	Pool          *redis.Pool
	StopChan      chan bool
	StoppedChan   chan bool
	Addr          string
	Proto         string
	Reconnecting  bool
	ParseWorkers  int
	BatchSize     int
	PerfStats     RedisInputPerfStats
	StatsEncoder  *util.PerformanceStatsEncoder
	UsePipelining bool
}

// GetName returns a printable name for the input
func (ri *RedisInput) GetName() string {
	return "Redis input"
}

func doParseJSON(inchan chan []byte, outchan chan types.Entry, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Info("started parse worker")
	for v := range inchan {
		e, err := util.ParseJSON(v)
		if err != nil {
			log.Warn(err, v)
			continue
		}
		outchan <- e
	}
}

func (ri *RedisInput) popPipeline(wg *sync.WaitGroup, stopChan chan bool,
	parseChan chan []byte) {
	var err error
	defer wg.Done()
	var skipLogs = false
	for {
		select {
		case <-stopChan:
			return
		default:
			conn := ri.Pool.Get()
			err = conn.Send("MULTI")
			if err != nil {
				if !skipLogs {
					log.Warnf("MULTI error %s, backing off (%v) and disabling further warnings", err.Error(), backOffTime)
					skipLogs = true
				}
				conn.Close()
				time.Sleep(backOffTime)
				continue
			} else {
				if skipLogs {
					skipLogs = false
					log.Warnf("MULTI succeeded, showing warnings again")
				}
			}
			for i := 0; i < ri.BatchSize; i++ {
				err = conn.Send("RPOP", "suricata")
				if err != nil {
					if !skipLogs {
						log.Warnf("RPOP error %s, backing off (%v) and disabling further warnings", err.Error(), backOffTime)
						skipLogs = true
					}
					conn.Close()
					time.Sleep(backOffTime)
					break
				} else {
					if skipLogs {
						skipLogs = false
						log.Warnf("RPOP sending succeeded, showing warnings again")
					}
				}
			}
			r, err := redis.Values(conn.Do("EXEC"))
			if err != nil {
				if !skipLogs {
					log.Warnf("EXEC error %s, backing off (%v) and disabling further warnings", err.Error(), backOffTime)
					skipLogs = true
				}
				conn.Close()
				continue
			} else {
				if skipLogs {
					skipLogs = false
					log.Warnf("EXEC sending succeeded, showing warnings again")
				}
			}
			conn.Close()
			for i, v := range r {
				if v == nil {
					if i == 0 {
						log.Debugf("empty result received, backing off (%v)", backOffTime)
						time.Sleep(backOffTime)
					}
					conn.Close()
					break
				} else {
					parseChan <- v.([]byte)
				}
			}
			conn.Close()
		}
	}
}

func (ri *RedisInput) noPipePop(wg *sync.WaitGroup, stopChan chan bool,
	parseChan chan []byte) {
	conn := ri.Pool.Get()
	defer wg.Done()
	defer conn.Close()
	for {
		select {
		case <-stopChan:
			return
		default:
			vals, err := redis.Values(conn.Do("BRPOP", "suricata", "1"))
			if vals != nil && err == nil && len(vals) > 0 {
				parseChan <- vals[1].([]byte)
			} else {
				time.Sleep(backOffTime)
				if err.Error() != "redigo: nil returned" && err != io.EOF {
					log.Warn(err)
					conn = ri.Pool.Get()
				}

			}
		}
	}
}

func (ri *RedisInput) handleServerConnection() {
	var wg sync.WaitGroup
	var parsewg sync.WaitGroup
	parseChan := make(chan []byte)
	pipelineStopChan := make(chan bool)

	for i := 0; i < ri.ParseWorkers; i++ {
		parsewg.Add(1)
		go doParseJSON(parseChan, ri.EventChan, &parsewg)
	}

	if ri.UsePipelining {
		wg.Add(1)
		go ri.popPipeline(&wg, pipelineStopChan, parseChan)
	} else {
		log.Info("Not using Redis pipelining.")
		wg.Add(3)
		go ri.noPipePop(&wg, pipelineStopChan, parseChan)
		go ri.noPipePop(&wg, pipelineStopChan, parseChan)
		go ri.noPipePop(&wg, pipelineStopChan, parseChan)
	}
	wg.Add(1)
	go ri.sendPerfStats(&wg)

	<-ri.StopChan
	close(pipelineStopChan)
	wg.Wait()
	close(parseChan)
	parsewg.Wait()
	close(ri.StoppedChan)
}

func (ri *RedisInput) sendPerfStats(wg *sync.WaitGroup) {
	defer wg.Done()
	start := time.Now()
	for {
		conn := ri.Pool.Get()
		select {
		case <-ri.StopChan:
			conn.Close()
			return
		default:
			if time.Since(start) > perfStatsSendInterval {
				if ri.StatsEncoder != nil {
					r, err := conn.Do("LLEN", "suricata")
					if err != nil {
						if err == io.EOF {
							conn.Close()
							time.Sleep(perfStatsSendInterval)
							continue
						} else {
							log.Warnf("error retrieving Redis list length: %s", err.Error())
						}
					} else {
						ri.PerfStats.RedisQueueLength, err = redis.Uint64(r, err)
						if err == nil {
							ri.StatsEncoder.Submit(ri.PerfStats)
						}
					}
				}
				start = time.Now()
			}
			time.Sleep(1 * time.Second)
		}
		conn.Close()
	}
}

// MakeRedisInput returns a new RedisInput, where the string parameter denotes a
// hostname:port combination.
func MakeRedisInput(addr string, outChan chan types.Entry, batchSize int) (*RedisInput, error) {
	var err error
	ri := &RedisInput{
		EventChan:    outChan,
		Verbose:      false,
		StopChan:     make(chan bool),
		Addr:         addr,
		Proto:        "tcp",
		ParseWorkers: 3,
		BatchSize:    batchSize,
		Pool: &redis.Pool{
			MaxIdle:     5,
			IdleTimeout: 240 * time.Second,
			Dial: func() (redis.Conn, error) {
				c, err := redis.Dial("tcp", addr)
				if err != nil {
					return nil, err
				}
				log.Infof("Dialing %s... result: %v", addr, err == nil)
				return c, err
			},
			TestOnBorrow: func(c redis.Conn, t time.Time) error {
				_, err := c.Do("PING")
				return err
			},
		},
	}
	return ri, err
}

// MakeRedisInputSocket returns a new RedisInput, where string parameter
// denotes a socket.
func MakeRedisInputSocket(addr string, outChan chan types.Entry, batchSize int) (*RedisInput, error) {
	var err error
	ri := &RedisInput{
		EventChan:    outChan,
		Verbose:      false,
		StopChan:     make(chan bool),
		Addr:         addr,
		Proto:        "unix",
		ParseWorkers: 3,
		BatchSize:    batchSize,
		Pool: &redis.Pool{
			MaxIdle:     5,
			IdleTimeout: 240 * time.Second,
			Dial: func() (redis.Conn, error) {
				c, err := redis.Dial("unix", addr)
				if err != nil {
					return nil, err
				}
				log.Infof("Dialing %s... result: %v", addr, err == nil)
				return c, err
			},
			TestOnBorrow: func(c redis.Conn, t time.Time) error {
				_, err := c.Do("PING")
				if err != nil {
					log.Println(err)
				}
				return err
			},
		},
	}
	return ri, err
}

// SubmitStats registers a PerformanceStatsEncoder for runtime stats submission.
func (ri *RedisInput) SubmitStats(sc *util.PerformanceStatsEncoder) {
	ri.StatsEncoder = sc
}

// Run starts the RedisInput
func (ri *RedisInput) Run() {
	if !ri.Running {
		ri.Running = true
		ri.StopChan = make(chan bool)
		go ri.handleServerConnection()
	}
}

// Stop causes the RedisInput to stop reading from the Redis list and close all
// associated channels, including the passed notification channel.
func (ri *RedisInput) Stop(stoppedChan chan bool) {
	if ri.Running {
		ri.StoppedChan = stoppedChan
		ri.StopChan <- true
		close(ri.StopChan)
		ri.Pool.Close()
		ri.Running = false
	}
}

// SetVerbose sets the input's verbosity level
func (ri *RedisInput) SetVerbose(verbose bool) {
	ri.Verbose = verbose
}
