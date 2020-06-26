# 🔥 FEVER [![CircleCI](https://circleci.com/gh/DCSO/fever.svg?style=svg)](https://circleci.com/gh/DCSO/fever)

The Fast, Extensible, Versatile Event Router (FEVER) is a tool for fast processing of events from Suricata's JSON EVE output. What is meant by 'processing' is defined by a number of modular components, for example facilitating fast ingestion into a database. Other processors implement collection, aggregation and forwarding of various metadata (e.g. aggregated and raw flows, passive DNS data, etc.) as well as performance metrics.

It is meant to be used in front of (or as a replacement for) general-purpose log processors like Logstash to increase event throughput as observed on sensors that see a lot of traffic.

## Building

Like any good Go program:

```
$ go get -t ./...
$ go build ./...
$ go install -v ./...
...
$ fever run -h
```

## Usage

```
$ ./fever run -h
The 'run' command starts the FEVER service, consuming events from
the input and executing all processing components.

Usage:
  fever run [flags]

Flags:
      --active-rdns                              enable active rDNS enrichment for src/dst IPs
      --active-rdns-cache-expiry duration        cache expiry interval for rDNS lookups (default 2m0s)
      --active-rdns-private-only                 only do active rDNS enrichment for RFC1918 IPs
      --bloom-alert-prefix string                String prefix for Bloom filter alerts (default "BLF")
      --bloom-blacklist-iocs strings             Blacklisted strings in Bloom filter (will cause filter to be rejected) (default [/,/index.htm,/index.html])
  -b, --bloom-file string                        Bloom filter for external indicator screening
  -z, --bloom-zipped                             use gzipped Bloom filter file
  -c, --chunksize uint                           chunk size for batched event handling (e.g. inserts) (default 50000)
      --context-cache-timeout duration           time for flow metadata to be kept for uncompleted flows (default 1h0m0s)
      --context-enable                           collect and forward flow context for alerted flows
      --context-submission-exchange string       Exchange to which flow context events will be submitted (default "context")
      --context-submission-url string            URL to which flow context will be submitted (default "amqp://guest:guest@localhost:5672/")
  -d, --db-database string                       database DB (default "events")
      --db-enable                                write events to database
  -s, --db-host string                           database host (default "localhost:5432")
      --db-maxtablesize uint                     Maximum allowed cumulative table size in GB (default 500)
  -m, --db-mongo                                 use MongoDB
  -p, --db-password string                       database password (default "sensor")
      --db-rotate duration                       time interval for database table rotations (default 1h0m0s)
  -u, --db-user string                           database user (default "sensor")
      --dummy                                    log locally instead of sending home
      --flowextract-bloom-selector string        IP address Bloom filter to select flows to extract
      --flowextract-enable                       extract and forward flow metadata
      --flowextract-submission-exchange string   Exchange to which raw flow events will be submitted (default "flows")
      --flowextract-submission-url string        URL to which raw flow events will be submitted (default "amqp://guest:guest@localhost:5672/")
  -n, --flowreport-interval duration             time interval for report submissions
      --flowreport-nocompress                    send uncompressed flow reports (default is gzip)
      --flowreport-submission-exchange string    Exchange to which flow reports will be submitted (default "aggregations")
      --flowreport-submission-url string         URL to which flow reports will be submitted (default "amqp://guest:guest@localhost:5672/")
      --flushcount uint                          maximum number of events in one batch (e.g. for flow extraction) (default 100000)
  -f, --flushtime duration                       time interval for event aggregation (default 1m0s)
  -T, --fwd-all-types                            forward all event types
  -t, --fwd-event-types strings                  event types to forward to socket (default [alert,stats])
  -h, --help                                     help for run
  -r, --in-redis string                          Redis input server (assumes "suricata" list key, no pwd)
      --in-redis-nopipe                          do not use Redis pipelining
  -i, --in-socket string                         filename of input socket (accepts EVE JSON) (default "/tmp/suri.sock")
      --ip-alert-prefix string                   String prefix for IP blacklist alerts (default "IP-BLACKLIST")
      --ip-blacklist string                      List with IP ranges to alert on
      --logfile string                           Path to log file
      --logjson                                  Output logs in JSON format
      --metrics-enable                           submit performance metrics to central sink
      --metrics-submission-exchange string       Exchange to which metrics will be submitted (default "metrics")
      --metrics-submission-url string            URL to which metrics will be submitted (default "amqp://guest:guest@localhost:5672/")
  -o, --out-socket string                        path to output socket (to forwarder), empty string disables forwarding (default "/tmp/suri-forward.sock")
      --pdns-enable                              collect and forward aggregated passive DNS data
      --pdns-submission-exchange string          Exchange to which passive DNS events will be submitted (default "pdns")
      --pdns-submission-url string               URL to which passive DNS events will be submitted (default "amqp://guest:guest@localhost:5672/")
      --profile string                           enable runtime profiling to given file
      --reconnect-retries uint                   number of retries connecting to socket or sink, 0 = no retry limit
      --stenosis-cache-expiry duration           alert cache expiry timeout (default 30m0s)
      --stenosis-client-chain-file string        certificate file for Stenosis TLS connection (default "stenosis.crt")
      --stenosis-client-key-file string          key file for Stenosis TLS connection (default "stenosis.key")
      --stenosis-enable                          notify Stenosis instance on alert
      --stenosis-root-cas strings                root certificate(s) for TLS connection to stenosis (default [root.crt])
      --stenosis-skipverify                      skip TLS certificate verification
      --stenosis-submission-timeout duration     timeout for connecting to Stenosis (default 5s)
      --stenosis-submission-url string           URL to which Stenosis requests will be submitted (default "http://localhost:19205")
      --stenosis-tls                             use TLS for Stenosis
      --toolname string                          set toolname (default "fever")
  -v, --verbose                                  enable verbose logging (debug log level)

Global Flags:
      --config string   config file (default is $HOME/.fever.yaml)
```

It is also possible to use a config file in YAML format ([Example](fever.yaml)). Configuration is cascading: first settings are loaded from the config file and can then be overridden by command line parameters.

## Running tests

The test suite requires a Redis executable in the current path. Most simply, this requirement can be satisfied by just installing Redis. For instance, via `apt`:

```
$ apt install redis-server
```

Then the test suite can be run via Go's generic testing framework:

```
$ go test -v -race -cover ./...
...
```

## Suricata settings

The tool is designed to consume JSON events from a socket, by default `/tmp/suri.sock`. This can be enabled using the following setting in `suricata.yaml`:
```yaml
...
# Extensible Event Format (nicknamed EVE) event log in JSON format
- eve-log:
    enabled: yes
    filetype: unix_stream
    filename: /tmp/suri.sock
    ...
```
All JSON is also passed through to another socket, which allows to plug it between Suricata and another log consumer, e.g. Logstash and friends.

Another way to consume events is via Redis. Use the `-r` parameters to specify a Redis host, the key `suricata` will be queried as a list to BRPOP events from.

## Important settings

- Database connection: use the `-db-*` parameters to specify a database connection. PostgreSQL 9.5 or later is required. Use `-m` to use the parameters as MongoDB connection parameters instead.
- Chunk size: determines the number of events that is imported as a whole at the same time. Larger values may be faster and lead to better throughput, but will use more RAM and also lose more events in case a bulk import (=transaction) fails. Smaller values will increase the overhead on the database.
- Profiling: optional output of a pprof file to be used with `go tool pprof`.
- Table rotation: tables are created as unlogged tables without indexes for maximal write performance. To keep table sizes in check, tables are timestamped and rotated in a time interval chosen by the user, e.g. 1h. Index creation is deferred until a table is rotated away and no longer written to, and also happens in the background. Indexing jobs are queued so if indexing takes longer than one rotation period, data should not be lost.
- Event forwarding: Events processed by FEVER can be forwarded to another socket to be processed by a downstream tool, e.g. Logstash. By default, only `alert` and `stats` event types are forwarded, but the set of forwarded types can be extended using `-t <type>` for additional types to be forwarded. As a catch-all (and probably the best option for sensors still running a full ELK stack) the option `-T` will forward everything.
- Bloom filters can be reloaded by sending a `SIGUSR1` to the main process.

## Development test runs with local data

Create local socket to consume forwarded events. You can also use [pv](http://www.ivarch.com/programs/pv.shtml) to monitor if data is flowing and how much (you may need to install the necessary tools using `apt install pv netcat-openbsd` before):

```bash
$ nc -klU /tmp/suri-forward.sock | pv > /dev/null
```

Instead of simply sending it to `/dev/null`, one can of course filter the output using `jq` etc. to visually confirm that certain output is forwarded.

Start the service:

```bash
$ ./fever run -v -n 0 -o '' --logfile '' &
```
The `-n 0` option disables submission of flow metadata. The `-o ''` disables forwarding to a local socket sink. Optionally, `--dummy`/`--nodb` can be used to disable database inserts and only test input parsing and metadata aggregation.

Finally, push test data into the input socket:

```bash
$ head -n 100000 huge.eve.json | socat /tmp/suri.sock STDIO
```
which would feed the first 100k events from `huge.eve.json` into the socket. The `socat` tool can be installed as usual via `apt install socat`.

To feed EVE data into FEVER using Redis (started with `-r`), you can simply LPUSH the JSON events into a list referenced by the key `suricata`. Use the Lua script `scripts/makelpush` to convert raw EVE lines into Redis statements:

```
$ head -n 100000 huge.eve.json | scripts/makelpush | redis-cli > /dev/null
```

## Author/Contact

Sascha Steinbiss

## License

BSD-3-clause
