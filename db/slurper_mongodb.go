package db

import (
	"encoding/json"
	"fmt"

	"github.com/DCSO/fever/types"

	log "github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2"
)

// TYPES are event types/collections supported by us
var TYPES = []string{
	"alert", "dns", "fileinfo", "flow",
	"http", "smtp", "ssh", "stats",
	"tls", "misc",
}

// MAXCOLLSIZEFRACTIONS are the proportions of the general space cap to be
// assigned to the collections for each event type -- used to determine
// limits for capped collections
var MAXCOLLSIZEFRACTIONS = map[string]float64{
	"dns":      0.25,
	"http":     0.2,
	"flow":     0.25,
	"smtp":     0.05,
	"ssh":      0.05,
	"alert":    0.05,
	"tls":      0.05,
	"stats":    0.02,
	"misc":     0.03,
	"fileinfo": 0.05,
}

// INDEXES assigns index parameters to each collection, denoted by the
// corresponding event type
var INDEXES = map[string]([]mgo.Index){
	"dns": []mgo.Index{
		//mgo.Index{
		//	Key: []string{"src_ip",
		//		"dest_ip"},
		//	Background: true,
		//},
		mgo.Index{
			Key:        []string{"dns.rrname"},
			Background: true,
		},
		mgo.Index{
			Key:        []string{"timestamp"},
			Background: true,
		},
	},
	"fileinfo": []mgo.Index{
		mgo.Index{
			Key: []string{"src_ip",
				"dest_ip"},
			Background: true,
		},
		mgo.Index{
			Key: []string{"fileinfo.filename",
				"fileinfo.md5"},
			Background: true,
		},
		mgo.Index{
			Key:        []string{"timestamp"},
			Background: true,
		},
	},
	"flow": []mgo.Index{
		mgo.Index{
			Key: []string{"src_ip",
				"dest_ip"},
			Background: true,
		},
		mgo.Index{
			Key:        []string{"timestamp"},
			Background: true,
		},
	},
	"http": []mgo.Index{
		mgo.Index{
			Key: []string{"src_ip",
				"dest_ip"},
			Background: true,
		},
		mgo.Index{
			Key: []string{"http.hostname",
				"http.http_user_agent"},
			Background: true,
		},
		mgo.Index{
			Key:        []string{"$text:http.url"},
			Background: true,
		},
		mgo.Index{
			Key:        []string{"timestamp"},
			Background: true,
		},
	},
	"alert": []mgo.Index{
		mgo.Index{
			Key: []string{"src_ip",
				"dest_ip"},
			Background: true,
		},
		mgo.Index{
			Key:        []string{"$text:alert.payload_printable"},
			Background: true,
		},
		mgo.Index{
			Key:        []string{"timestamp"},
			Background: true,
		},
	},
	"smtp": []mgo.Index{
		mgo.Index{
			Key: []string{"src_ip",
				"dest_ip"},
			Background: true,
		},
		mgo.Index{
			Key: []string{"smtp.helo",
				"smtp.mail_from",
				"smtp.rcpt_to"},
			Background: true,
		},
		mgo.Index{
			Key:        []string{"email.attachment"},
			Background: true,
		},
		mgo.Index{
			Key:        []string{"timestamp"},
			Background: true,
		},
	},
	"tls": []mgo.Index{
		mgo.Index{
			Key: []string{"src_ip",
				"dest_ip"},
			Background: true,
		},
		mgo.Index{
			Key: []string{"tls.subject",
				"tls.issuerdn",
				"tls.fingerprint"},
			Background: true,
		},
		mgo.Index{
			Key:        []string{"timestamp"},
			Background: true,
		},
	},
	"misc": []mgo.Index{
		mgo.Index{
			Key: []string{"src_ip",
				"dest_ip"},
			Background: true,
		},
		mgo.Index{
			Key:        []string{"timestamp"},
			Background: true,
		},
	},
}

// MongoSlurper is a Slurper that stores events in an MongoDB database.
type MongoSlurper struct {
	User         string
	Password     string
	Host         string
	Database     string
	TypeDispatch map[string](chan types.Entry)
	ChunkSize    int
	MaxSize      int64
	Logger       *log.Entry
}

func (s *MongoSlurper) eventTypeWorker(eventchan chan types.Entry, eventType string) error {
	var err error
	cnt := 0
	url := fmt.Sprintf("mongodb://%s:%s@%s/%s", s.User, s.Password, s.Host, s.Database)
	s.Logger.WithFields(log.Fields{"type": eventType}).Info("worker connecting")
	sess, err := mgo.Dial(url)
	if err != nil {
		s.Logger.Fatal(err)
		return err
	}
	s.Logger.WithFields(log.Fields{"type": eventType}).Info("connection established")
	db := sess.DB(s.Database)

	// create capped collection
	coll := db.C(eventType)
	sizeFrac := MAXCOLLSIZEFRACTIONS[eventType]
	if sizeFrac == 0 {
		s.Logger.Warn("Invalid type", eventType, "no max size available for collection")
		sizeFrac = 0.01
	}
	s.Logger.WithFields(log.Fields{"type": eventType, "sizeFrac": sizeFrac}).Info("determining size fraction")
	sizeBytes := int(float64(s.MaxSize) * sizeFrac)
	s.Logger.WithFields(log.Fields{"type": eventType, "maxSize": sizeBytes}).Info("determining size cap")
	err = coll.Create(&mgo.CollectionInfo{
		Capped:         true,
		DisableIdIndex: true,
		MaxBytes:       sizeBytes,
	})
	if err != nil {
		s.Logger.WithFields(log.Fields{"type": eventType}).Info(err)
	}
	// check indexes on collection, create if needed
	idxList := INDEXES[eventType]
	if idxList != nil {
		s.Logger.WithFields(log.Fields{"type": eventType}).Info("checking indexes")
		for _, idx := range idxList {
			s.Logger.WithFields(log.Fields{"type": eventType, "idx": idx.Key}).Info("index check")
			coll.EnsureIndex(idx)
		}
		s.Logger.WithFields(log.Fields{"type": eventType}).Info("index check done")
	}

	b := coll.Bulk()
	b.Unordered()
	for event := range eventchan {
		var ev map[string]interface{}
		err := json.Unmarshal([]byte(event.JSONLine), &ev)
		if err != nil {
			s.Logger.Warn(err)
		} else {
			b.Insert(&ev)
			cnt++
			if cnt%s.ChunkSize == 0 {
				s.Logger.WithFields(log.Fields{"type": eventType}).Debugf("flushing bulk")
				_, err = b.Run()
				if err != nil {
					s.Logger.Warn(err)
				} else {
					s.Logger.WithFields(log.Fields{"type": eventType}).Debugf("flushing complete")
				}
				b = coll.Bulk()
				b.Unordered()
				cnt = 0
			}
		}
	}
	return nil
}

// MakeMongoSlurper creates a new MongoSlurper instance.
func MakeMongoSlurper(host string, database string, user string, password string, chunkSize int, maxSize int64) *MongoSlurper {
	s := &MongoSlurper{
		ChunkSize:    chunkSize,
		Host:         host,
		Database:     database,
		User:         user,
		Password:     password,
		TypeDispatch: make(map[string](chan types.Entry)),
		MaxSize:      maxSize * 1024 * 1024 * 1024,
		Logger:       log.WithFields(log.Fields{"domain": "slurper", "slurper": "mongo"}),
	}
	for _, t := range TYPES {
		s.TypeDispatch[t] = make(chan types.Entry, 1000)
	}
	url := fmt.Sprintf("mongodb://%s:%s@%s/%s", s.User, s.Password, s.Host, s.Database)
	s.Logger.WithFields(log.Fields{"url": url}).Info("preparing for MongoDB connection")
	return s
}

// Run starts a MongoSlurper.
func (s *MongoSlurper) Run(eventchan chan types.Entry) {
	// set up workers for each event type
	for k, v := range s.TypeDispatch {
		go s.eventTypeWorker(v, k)
	}
	// dispatch events to their corresponding worker
	go func() {
		for entry := range eventchan {
			targetchan := s.TypeDispatch[entry.EventType]
			if targetchan != nil {
				targetchan <- entry
			} else {
				s.TypeDispatch["misc"] <- entry
			}
		}
	}()
}

// Finish is a null operation in the MongoSlurper implementation.
func (s *MongoSlurper) Finish() {
}
