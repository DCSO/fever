package db

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/DCSO/fever/types"

	"github.com/jackc/pgx/v4/pgxpool"
	log "github.com/sirupsen/logrus"
)

var maxRetries = 20

// PostgresSlurper is a Slurper that stores events in an PostgreSQL database.
type PostgresSlurper struct {
	DB     *pgxpool.Pool
	DBUser string
	// CopyFn allows injecting a custom COPY executor for testing.
	// It should execute a COPY FROM STDIN using the provided SQL and reader and return rows copied.
	CopyFn func(ctx context.Context, pool *pgxpool.Pool, sql string, r io.Reader) (int64, error)
	// ExecFn allows injecting execution for DDL statements (e.g., CREATE TABLE ... GRANT ...)
	ExecFn           func(ctx context.Context, sql string) error
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
	dsn := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", user, password, host, database)
	cfg, cfgErr := pgxpool.ParseConfig(dsn)
	if cfgErr != nil {
		log.WithError(cfgErr).Fatal("failed to parse pgx config")
	}
	db, err := pgxpool.ConnectConfig(context.Background(), cfg)
	if err != nil {
		log.WithError(err).Fatal("failed to connect to postgres via pgxpool")
	}
	l := log.WithFields(log.Fields{
		"domain":  "slurper",
		"slurper": "postgres",
	})
	l.WithFields(log.Fields{
		"user":     user,
		"host":     host,
		"database": database,
	}).Info("connected to database")
	for i = 0; ; i++ {
		err = db.QueryRow(context.Background(), SQLCheckForTrigramExtension).Scan(&hasExt)
		if err == nil || i > maxRetries || !strings.Contains(err.Error(), "system is starting up") {
			break
		}
		l.Warnf("problem checking for trigram extension: %s -- retrying %d/%d",
			err.Error(), i, maxRetries)
		time.Sleep(10 * time.Second)
	}
	if err != nil {
		l.Fatalf("permanent error checking for trigram extension: %s", err.Error())
	}
	if hasExt < 1 {
		l.Fatal("trigram extension ('pg_trgm') not loaded, please run "+
			"'CREATE EXTENSION pg_trgm;'", err)
	}
	_, err = db.Exec(context.Background(), SQLTrigramFunction)
	if err != nil {
		l.Fatalf("error creating index preparation function: %s", err)
	}
	_, err = db.Exec(context.Background(), SQLQueryAllEvents)
	if err != nil {
		l.Fatalf("error creating global query function: %s", err)
	}
	s := &PostgresSlurper{
		DB:               db,
		DBUser:           user,
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

func (s *PostgresSlurper) expireOldTables(ctx context.Context) error {
	rows, err := s.DB.Query(ctx, SQLGetTableSizes)
	if err != nil {
		s.Logger.Warn("error determining table sizes", err)
		return err
	}
	defer rows.Close()
	var tblSizes []tableSize
	for rows.Next() {
		var t tableSize
		if err := rows.Scan(&t.Table, &t.Size); err != nil {
			s.Logger.WithError(err).Warn("error scanning table size row")
			return err
		}
		tblSizes = append(tblSizes, t)
	}
	totalSize := int64(0)
	for _, v := range tblSizes {
		totalSize += v.Size
		if totalSize > s.MaxTableSize && s.CurrentTableName != v.Table {
			s.Logger.WithFields(log.Fields{
				"table": v.Table,
				"size":  v.Size,
			}).Info("table expired")
			_, err = s.DB.Exec(ctx, fmt.Sprintf(`DROP TABLE "%s";`, v.Table))
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

func (s *PostgresSlurper) indexFunc(ctx context.Context) {
	for tblToIndex := range s.IndexChan {
		s.Logger.WithFields(log.Fields{
			"table": tblToIndex,
		}).Info("creating indexes")
		idxSQL := fmt.Sprintf(SQLIndex, tblToIndex, tblToIndex, tblToIndex,
			tblToIndex, tblToIndex)
		_, idxErr := s.DB.Exec(ctx, idxSQL)
		if idxErr != nil {
			s.Logger.WithFields(log.Fields{
				"table": tblToIndex,
				"error": idxErr.Error(),
			}).Info("error creating index")
		}
		s.Logger.Info("expiring old tables")
		s.expireOldTables(ctx)
	}
}

func (s *PostgresSlurper) slurpPostgres(ctx context.Context, eventchan chan types.Entry) {
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
				crSQL := fmt.Sprintf(SQLCreate, newTableName, newTableName, s.DBUser)
				var crErr error
				// Use ExecFn if provided, otherwise use DB.Exec
				if s.ExecFn != nil {
					crErr = s.ExecFn(ctx, crSQL)
				} else {
					_, crErr = s.DB.Exec(ctx, crSQL)
				}
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
			// Use a reader-based COPY to stream the entire buffer
			sql := fmt.Sprintf(SQLCopy, s.CurrentTableName)
			r := strings.NewReader(copybuf.String())
			var err error
			// Use CopyFn if provided, otherwise use DB.CopyFrom
			if s.CopyFn != nil {
				_, err = s.CopyFn(ctx, s.DB, sql, r)
			} else {
				conn, acqErr := s.DB.Acquire(ctx)
				if acqErr != nil {
					s.Logger.WithError(acqErr).Warn("failed to acquire connection for COPY")
					copybuf.Reset()
					continue
				}
				_, err = conn.Conn().PgConn().CopyFrom(ctx, r, sql)
				conn.Release()
			}
			if err != nil {
				s.Logger.Warn(err)
			} else {
				s.Logger.WithFields(log.Fields{
					"chunksize": s.ChunkSize,
					"table":     s.CurrentTableName,
				}).Debug("COPY complete")
			}
			copybuf.Reset()
		}
		cnt++
	}
}

// Run starts a PostgresSlurper.
func (s *PostgresSlurper) Run(ctx context.Context, eventchan chan types.Entry) {
	// start indexer thread
	s.IndexChan = make(chan string, 1000)
	go s.indexFunc(ctx)
	// run slurper thread
	go s.slurpPostgres(ctx, eventchan)
}

// Finish is a null operation in the PostgresSlurper implementation.
func (s *PostgresSlurper) Finish() {
}
