//go:build ignore
// +build ignore

package db

import (
	"github.com/mkilling/goejdb"
	log "github.com/sirupsen/logrus"
)

// EJDBSlurper is a Slurper that stores events in an EJDB database.
type EJDBSlurper struct {
	db *goejdb.Ejdb
}

// Run starts an EJDBSlurper.
func (s *EJDBSlurper) Run(eventchan chan Entry) {
	var err error
	i := 0
	s.db, err = goejdb.Open("eventsdb", goejdb.JBOWRITER|goejdb.JBOCREAT)
	if err != nil {
		log.Warn(err)
	}
	coll, _ := s.db.CreateColl("events", nil)
	coll.SetIndex("timestamp", goejdb.JBIDXSTR)
	coll.SetIndex("event_type", goejdb.JBIDXSTR)
	coll.SetIndex("dns.rrname", goejdb.JBIDXSTR)
	coll.SetIndex("alert.payload_printable", goejdb.JBIDXSTR)
	go func() {
		coll.BeginTransaction()
		for d := range eventchan {
			if i%5000 == 0 {
				coll.CommitTransaction()
				coll.BeginTransaction()
			}
			coll.SaveJson(d.JSONLine)
			i++
		}
	}()
}

// Finish closes the associated EJDB database..
func (s *EJDBSlurper) Finish() {
	s.db.Close()
}
