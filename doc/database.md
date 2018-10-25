## Database schema

Events are stored in a JSONB column tagged with a timestamp. Indexes will be created on this timestamp, the source/destination IP/port values (composite), and the event type. Another full-text (trigram) index will be built for event type-specific plain-text fields that are concatenated using a `|`. The keyword-based full-text matches are intended to serve as the main means of access to 'interesting' events, and can be further refined by IP/port/type/... constraints, which are also indexed. All further queries on JSON fields **will be unindexed**, so care should be taken to reduce the search space as much as possible using indexed queries.

A separate database must be used and the connecting user must be able to `CREATE` and `DROP` tables in the public schema.

```sql
-- Initial table
CREATE UNLOGGED TABLE IF NOT EXISTS "events-YY-MM-DD-HHMM"
  (ts timestamp without time zone default now(),
   payload jsonb);
GRANT ALL PRIVILEGES ON TABLE "events-YY-MM-DD-HHMM" to sensor;

-- Deferred
CREATE INDEX ON "events-YY-MM-DD-HHMM" (ts);
CREATE INDEX ON "events-YY-MM-DD-HHMM" (((payload->>'src_ip')::INET), ((payload->>'src_port')::INT));
CREATE INDEX ON "events-YY-MM-DD-HHMM" (((payload->>'dest_ip')::INET), ((payload->>'dest_port')::INT));
CREATE INDEX ON "events-YY-MM-DD-HHMM" ((payload->>'event_type'));
CREATE INDEX ON "events-YY-MM-DD-HHMM" using GIN (trigram_string(payload) gin_trgm_ops)
```
`trigram_string(payload jsonb)` is a PL/PgSQL function that extracts and concatenates relevant data for indexing, see `sql.go`.

The following contents are used to build the full-text index:

 - `dns` events:
   - `dns->rdata`
 - `http` events:
   - `http->hostname` + `http->url` + `http->http_user_agent`
 - `tls` events:
  -  `tls->subject` + `tls->issuerdn` + `tls->fingerprint`
 - `alert` events:
  - `alert->payload_printable` + `alert->payload`
 - `smtp` events:
  - `smtp->helo` + `smtp->mail_from` + `smtp->rcpt_to` + `email->from`+ `email->to` + `email->attachment`
 - `fileinfo` events:
  - `fileinfo->filename` + `fileinfo->md5`