package db

import (
	"bytes"
	"io"
	"testing"
	"time"

	"context"
	"regexp"

	"github.com/DCSO/fever/types"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestPostgresSlurperCopyBufferContents(t *testing.T) {
	var capturedSQL string
	var capturedBody []byte
	done := make(chan struct{}, 1)

	s := &PostgresSlurper{
		DB:               (*pgxpool.Pool)(nil),
		DBUser:           "testuser",
		LastRotatedTime:  time.Now(),
		IndexChan:        make(chan string, 1),
		CurrentTableName: "event-2025-01-01-0000",
		RotationInterval: time.Hour,
		MaxTableSize:     1 << 30,
		ChunkSize:        1,
		Logger:           logrus.WithField("test", "pgx-copy"),
	}

	// CopyFn to capture SQL and the entire reader body
	s.CopyFn = func(ctx context.Context, pool *pgxpool.Pool, sql string, r io.Reader) (int64, error) {
		capturedSQL = sql
		b, _ := io.ReadAll(r)
		capturedBody = b
		done <- struct{}{}
		return int64(bytes.Count(b, []byte("\n"))), nil
	}

	events := []types.Entry{
		{Timestamp: "2023-01-01T12:00:00Z", JSONLine: `{"k":"v1"}`},
		{Timestamp: "2023-01-01T12:00:01Z", JSONLine: `{"k":"v2"}`},
	}
	expectedBody := "2023-01-01T12:00:00Z\t{\"k\":\"v1\"}\n" +
		"2023-01-01T12:00:01Z\t{\"k\":\"v2\"}\n"
	expectedSQL := "COPY \"" + s.CurrentTableName + "\" (ts, payload) FROM STDIN WITH CSV DELIMITER E'\\t' QUOTE E'\\b'"

	eventCh := make(chan types.Entry, len(events)+1)
	go s.slurpPostgres(context.TODO(), eventCh)

	// send exactly 2 events to trigger a copy
	for _, e := range events {
		eventCh <- e
	}

	select {
	case <-done:
		// proceed
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for COPY to be invoked")
	}

	assert.Equal(t, expectedSQL, capturedSQL, "COPY SQL should match expected")
	assert.Equal(t, expectedBody, string(capturedBody), "COPY body should equal concatenation of lines with tab and newline")
}

func TestPostgresSlurperRotateCreateAndCopy(t *testing.T) {
	var capturedExecSQL string
	var capturedCopySQL string
	var capturedBody []byte
	done := make(chan struct{}, 1)

	s := &PostgresSlurper{
		DB:               (*pgxpool.Pool)(nil),
		DBUser:           "testuser",
		LastRotatedTime:  time.Now().Add(-2 * time.Second),
		IndexChan:        make(chan string, 1),
		CurrentTableName: "event-old",
		RotationInterval: time.Millisecond,
		MaxTableSize:     1 << 30,
		ChunkSize:        1,
		Logger:           logrus.WithField("test", "pgx-rotate"),
	}

	// ExecFn to capture CREATE/GRANT SQL
	s.ExecFn = func(ctx context.Context, sql string) error {
		capturedExecSQL = sql
		return nil
	}
	// CopyFn to capture COPY SQL and body
	s.CopyFn = func(ctx context.Context, pool *pgxpool.Pool, sql string, r io.Reader) (int64, error) {
		capturedCopySQL = sql
		b, _ := io.ReadAll(r)
		capturedBody = b
		done <- struct{}{}
		return int64(bytes.Count(b, []byte("\n"))), nil
	}

	events := []types.Entry{
		{Timestamp: "2023-01-01T12:00:00Z", JSONLine: `{"k":"v1"}`},
		{Timestamp: "2023-01-01T12:00:01Z", JSONLine: `{"k":"v2"}`},
	}
	expectedBody := "2023-01-01T12:00:00Z\t{\"k\":\"v1\"}\n" +
		"2023-01-01T12:00:01Z\t{\"k\":\"v2\"}\n"

	eventCh := make(chan types.Entry, len(events)+1)
	go s.slurpPostgres(context.Background(), eventCh)
	for _, e := range events {
		eventCh <- e
	}

	select {
	case <-done:
		// proceed
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for COPY to be invoked")
	}

	// Assert CREATE/GRANT executed for event-YYYY-mm-dd-HHMM
	createRegex := regexp.MustCompile(`CREATE UNLOGGED TABLE IF NOT EXISTS "event-[0-9-]+"\s*\(ts timestamp without time zone default now\(\),\s*payload jsonb\);\s*GRANT ALL PRIVILEGES ON TABLE "event-[0-9-]+" to testuser;`)
	assert.Regexp(t, createRegex, capturedExecSQL, "CREATE/GRANT SQL should match expected pattern")

	// Assert COPY SQL targets an event-YYYY.. table and uses correct options
	copyRegex := regexp.MustCompile(`^COPY "event-[0-9-]+" \(ts, payload\) FROM STDIN WITH CSV DELIMITER E'\\t' QUOTE E'\\b'$`)
	assert.Regexp(t, copyRegex, capturedCopySQL, "COPY SQL should target rotated table with correct format")

	// Assert body
	assert.Equal(t, expectedBody, string(capturedBody), "COPY body should equal concatenation of lines")

	// Assert that previous table was enqueued for indexing upon rotation
	select {
	case prev := <-s.IndexChan:
		assert.Equal(t, "event-old", prev, "previous table should be enqueued after rotation")
	default:
		t.Fatalf("expected previous table to be enqueued for indexing")
	}
}
