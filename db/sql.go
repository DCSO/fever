package db

// DCSO FEVER
// Copyright (c) 2017, DCSO GmbH

// SQLTrigramFunction is a plpgsql function to pull out indexable content from event JSON
const SQLTrigramFunction = `CREATE OR REPLACE FUNCTION trigram_string(payload jsonb)
RETURNS text
AS $$
DECLARE
	buffer varchar := '';
BEGIN
  -- trying in typical order of frequency
  IF payload->>'event_type' = 'dns'
  THEN
    RETURN payload->'dns'->>'rdata';
  END IF;
  IF payload->>'event_type' = 'http'
  THEN
    RETURN (payload->'http'->>'hostname') || '|' || (payload->'http'->>'url') || '|' || (payload->'http'->>'http_user_agent');
  END IF;
  IF payload->>'event_type' = 'tls'
  THEN
    RETURN (payload->'tls'->>'subject') ||'|' || (payload->'tls'->>'issuerdn') || '|' || (payload->'tls'->>'fingerprint');
  END IF;
  IF payload->>'event_type' = 'alert'
  THEN
    RETURN (payload->'alert'->>'payload_printable')  || '|' || (payload->'alert'->>'payload');
  END IF;
  IF payload->>'event_type' = 'smtp'
  THEN
    RETURN (payload->'smtp'->>'helo') || '|' || (payload->'smtp'->>'mail_from') || '|' || (payload->'smtp'->>'rcpt_to') || '|' || (payload->'email'->>'from') || '|' || (payload->'email'->>'to') || '|' || (payload->'email'->>'attachment');
  END IF;
  IF payload->>'event_type' = 'fileinfo'
  THEN
    RETURN (payload->'fileinfo'->>'filename') || '|' || (payload->'fileinfo'->>'md5');
  END IF;
	RETURN buffer;
END;
$$
LANGUAGE plpgsql
IMMUTABLE;`

// SQLCheckForTrigramExtension is an SQL query to check whether the trigram extension is available.
const SQLCheckForTrigramExtension = `SELECT COUNT(*) FROM pg_available_extensions WHERE name = 'pg_trgm';`

// SQLCreate is an SQL/DDL clause to create a new event table
const SQLCreate = `CREATE UNLOGGED TABLE IF NOT EXISTS "%s"
  (ts timestamp without time zone default now(),
   payload jsonb);
GRANT ALL PRIVILEGES ON TABLE "%s" to %s;`

// SQLCopy is an SQL/DDL clause to bulk insert a chunk of JSON into the database
const SQLCopy = `COPY "%s" (ts, payload) FROM STDIN WITH CSV DELIMITER E'\t' QUOTE E'\b'`

// SQLIndex is an SQL/DDL clause to create indexes on event tables
const SQLIndex = `CREATE INDEX ON "%s" (((payload->>'src_ip')::INET), ((payload->>'src_port')::INT));
CREATE INDEX ON "%s" (ts);
CREATE INDEX ON "%s" (((payload->>'dest_ip')::INET), ((payload->>'dest_port')::INT));
CREATE INDEX ON "%s" ((payload->>'event_type'));
CREATE INDEX ON "%s" using GIN (trigram_string(payload) gin_trgm_ops)`

// SQLGetTableSizes is an SQL query to obtain the names of tables in the current schema and their size in bytes.
const SQLGetTableSizes = `SELECT relname as table,
 pg_total_relation_size(relid) as size
 FROM pg_catalog.pg_statio_user_tables
 ORDER BY 1 DESC;`

// SQLGenericQuery is the main kind of query used to pull out event metadata.
const SQLGenericQuery = `SELECT * FROM all_events_query($1::text, $2::timestamp, $3::timestamp, $4::text[], $5::inet, $6::int, $7::inet, $8::int, $9::int);`

// SQLQueryAllEvents is a plpgsql function to enable queries over all hourly tables
// Example: SELECT COUNT(*) FROM all_events_query('WHERE trigram_string(payload) LIKE ''%%foo%%''');
const SQLQueryAllEvents = `CREATE OR REPLACE FUNCTION all_events_query(keyword text,
                                            start_time timestamp with time zone,
                                            end_time timestamp with time zone,
                                            event_type text[],
                                            ipsrc inet, portsrc int,
                                            ipdest inet, portdest int,
                                            mlimit int)
 RETURNS TABLE (ts timestamp, payload jsonb)
 AS $$
 DECLARE
   clause text;
   t RECORD;
   tables CURSOR FOR
        SELECT * FROM information_schema.tables
        WHERE table_name LIKE 'event%';
 BEGIN
  clause := '';
  OPEN tables;

  LOOP
    FETCH tables INTO t;
    EXIT WHEN NOT FOUND;
    IF clause != '' THEN
      clause := clause || ' UNION ALL ';
    END IF;
    clause := clause
      || 'SELECT * FROM ' || quote_ident(t.table_name)
      || ' WHERE ts BETWEEN ' || quote_literal(start_time)
      || ' AND ' || quote_literal(end_time);
    IF keyword IS NOT NULL THEN
      clause := clause
        || ' AND trigram_string(payload) LIKE ' || quote_literal(keyword);
    END IF;
    IF event_type IS NOT NULL THEN
      clause := clause
        || ' AND payload->>''event_type'' = ANY(' || quote_literal(event_type) || ')';
    END IF;
    IF ipsrc IS NOT NULL THEN
      clause := clause
        || ' AND (payload->>''src_ip'')::inet <<= inet ' || quote_literal(ipsrc);
    END IF;
    IF portsrc IS NOT NULL THEN
      clause := clause
        || ' AND payload->>''src_port'' = ' || quote_literal(portsrc);
    END IF;
    IF ipdest IS NOT NULL THEN
      clause := clause
        || ' AND (payload->>''dest_ip'')::inet <<= inet ' || quote_literal(ipdest);
    END IF;
    IF portdest IS NOT NULL THEN
      clause := clause
        || ' AND payload->>''dest_port'' = ' || quote_literal(portdest);
    END IF;
  END LOOP;

  IF mlimit IS NOT NULL THEN
    clause := clause || ' LIMIT ' || quote_literal(mlimit);
  END IF;

  RAISE NOTICE '%', clause;

  CLOSE tables;
  RETURN QUERY EXECUTE clause;
 END;
 $$
 LANGUAGE plpgsql
 STABLE;
`
