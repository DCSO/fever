package db

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/DCSO/fever/types"

	log "github.com/sirupsen/logrus"
	pg "gopkg.in/pg.v5"
)

var maxRetries = 20

// PostgresSlurper is a Slurper that stores events in an PostgreSQL database.
type PostgresSlurper struct {
	DB               *pg.DB
	LastRotatedTime  time.Time
	IndexChan        chan string
	CurrentTableName string
	RotationInterval time.Duration
	MaxTableSize     int64
	ChunkSize        int
	Logger           *log.Entry
}

// This is a fixed format for table names.
func formatTableName(timestamp time.Time) string {
	return timestamp.Format("event-2006-01-02-1504")
}

// MakePostgresSlurper creates a new PostgresSlurper instance.
func MakePostgresSlurper(host string, database string, user string,
	password string, rotationInterval time.Duration,
	maxTableSize int64, chunkSize int) *PostgresSlurper {
	var err error
	var i int
	var hasExt int
	db := pg.Connect(&pg.Options{
		User:     user,
		Password: password,
		Addr:     host,
		Database: database,
	})
	l := log.WithFields(log.Fields{
		"domain":  "slurper",
		"slurper": "postgres",
	})
	l.WithFields(log.Fields{
		"user":     user,
		"host":     host,
		"database": database,
	}).Info("connected to database")
	_, err = db.Query(pg.Scan(&hasExt), SQLCheckForTrigramExtension)
	for i = 0; err != nil && strings.Contains(err.Error(), "system is starting up"); i++ {
		if i > maxRetries {
			break
		}
		l.Warnf("problem checking for trigram extension: %s -- retrying %d/%d",
			err.Error(), i, maxRetries)
		_, err = db.Query(pg.Scan(&hasExt), SQLCheckForTrigramExtension)
		time.Sleep(10 * time.Second)
	}
	if err != nil {
		l.Fatalf("permanent error checking for trigram extension: %s", err.Error())
	}
	if hasExt < 1 {
		l.Fatal("trigram extension ('pg_trgm') not loaded, please run "+
			"'CREATE EXTENSION pg_trgm;'", err)
	}
	_, err = db.Exec(SQLTrigramFunction)
	if err != nil {
		l.Fatalf("error creating index preparation function: %s", err)
	}
	_, err = db.Exec(SQLQueryAllEvents)
	if err != nil {
		l.Fatalf("error creating global query function: %s", err)
	}
	s := &PostgresSlurper{
		DB:               db,
		RotationInterval: rotationInterval,
		MaxTableSize:     maxTableSize * 1024 * 1024 * 1024,
		ChunkSize:        chunkSize,
		Logger:           l,
	}
	return s
}

type tableSize struct {
	Table string
	Size  int64
}

func (s *PostgresSlurper) expireOldTables() error {
	var tblSizes []tableSize
	_, err := s.DB.Query(&tblSizes, SQLGetTableSizes)
	if err != nil {
		s.Logger.Warn("error determining table sizes", err)
		return err
	}
	totalSize := int64(0)
	for _, v := range tblSizes {
		totalSize += v.Size
		if totalSize > s.MaxTableSize && s.CurrentTableName != v.Table {
			s.Logger.WithFields(log.Fields{
				"table": v.Table,
				"size":  v.Size,
			}).Info("table expired")
			_, err = s.DB.Exec(fmt.Sprintf(`DROP TABLE "%s";`, v.Table))
			if err != nil {
				s.Logger.WithFields(log.Fields{
					"table": v.Table,
					"size":  v.Size,
					"error": err.Error(),
				}).Warn("error dropping table")
				return err
			}
		}
	}
	return nil
}

func (s *PostgresSlurper) indexFunc() {
	for tblToIndex := range s.IndexChan {
		s.Logger.WithFields(log.Fields{
			"table": tblToIndex,
		}).Info("creating indexes")
		idxSQL := fmt.Sprintf(SQLIndex, tblToIndex, tblToIndex, tblToIndex,
			tblToIndex, tblToIndex)
		_, idxErr := s.DB.Exec(idxSQL)
		if idxErr != nil {
			s.Logger.WithFields(log.Fields{
				"table": tblToIndex,
				"error": idxErr.Error(),
			}).Info("error creating index")
		}
		s.Logger.Info("expiring old tables")
		s.expireOldTables()
	}
}

func (s *PostgresSlurper) slurpPostgres(eventchan chan types.Entry) {
	cnt := 0
	var copybuf bytes.Buffer
	for {
		event := <-eventchan
		copybuf.WriteString(event.Timestamp)
		copybuf.WriteString("\t")
		copybuf.WriteString(event.JSONLine)
		copybuf.WriteString("\n")
		if cnt > 0 && cnt%s.ChunkSize == 0 {
			if s.LastRotatedTime.IsZero() || (time.Since(s.LastRotatedTime) > s.RotationInterval) {
				newTableName := formatTableName(time.Now())
				if s.LastRotatedTime.IsZero() {
					s.Logger.WithFields(log.Fields{
						"table": newTableName,
					}).Info("initializing table")
				} else {
					s.Logger.WithFields(log.Fields{
						"from": s.CurrentTableName,
						"to":   newTableName,
					}).Info("rotating tables")
				}
				crSQL := fmt.Sprintf(SQLCreate, newTableName, newTableName, s.DB.Options().User)
				_, crErr := s.DB.Exec(crSQL)
				if crErr != nil {
					s.Logger.WithFields(log.Fields{
						"table": newTableName,
						"error": crErr.Error(),
					}).Warn("error creating table")
				}
				if !s.LastRotatedTime.IsZero() {
					s.IndexChan <- s.CurrentTableName
				}
				s.CurrentTableName = newTableName
				s.LastRotatedTime = time.Now()
			}
			cnt = 0
			r := strings.NewReader(copybuf.String())
			_, err := s.DB.CopyFrom(r, fmt.Sprintf(SQLCopy, s.CurrentTableName))
			if err != nil {
				s.Logger.Warn(err)
			} else {
				s.Logger.WithFields(log.Fields{
					"chunksize": s.ChunkSize,
					"table":     s.CurrentTableName,
				}).Info("COPY complete")
			}
			copybuf.Reset()
		}
		cnt++
	}
}

// Run starts a PostgresSlurper.
func (s *PostgresSlurper) Run(eventchan chan types.Entry) {
	// start indexer thread
	s.IndexChan = make(chan string, 1000)
	go s.indexFunc()
	// run slurper thread
	go s.slurpPostgres(eventchan)
}

// Finish is a null operation in the PostgresSlurper implementation.
func (s *PostgresSlurper) Finish() {
}
