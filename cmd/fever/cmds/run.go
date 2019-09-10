package cmd

// DCSO FEVER
// Copyright (c) 2017, 2018, 2019, DCSO GmbH

import (
	"io"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"
	"time"

	"github.com/DCSO/fever/db"
	"github.com/DCSO/fever/input"
	"github.com/DCSO/fever/processing"
	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"

	"github.com/NeowayLabs/wabbit"
	"github.com/NeowayLabs/wabbit/amqp"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var dispatcher *processing.HandlerDispatcher
var forward bool

const defaultQueueSize = 50000

func mainfunc(cmd *cobra.Command, args []string) {
	var s db.Slurper
	var err error
	var submitter util.StatsSubmitter
	var statssubmitter util.StatsSubmitter
	var pse *util.PerformanceStatsEncoder

	eventChan := make(chan types.Entry, defaultQueueSize)

	util.ToolName = viper.GetString("toolname")

	logfilename := viper.GetString("logging.file")
	if len(logfilename) > 0 {
		log.Println("Switching to log file", logfilename)
		file, err := os.OpenFile(logfilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		log.SetFormatter(&log.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		})
		log.SetOutput(file)
	}

	logjson := viper.GetBool("logging.json")
	if logjson {
		log.SetFormatter(&log.JSONFormatter{})
	}

	verbose := viper.GetBool("verbose")
	if verbose {
		log.Info("verbose log output enabled")
		log.SetLevel(log.DebugLevel)
	}

	dummyMode := viper.GetBool("dummy")

	enableMetrics := viper.GetBool("metrics.enable")
	if err != nil {
		log.Fatal(err)
	}
	if enableMetrics {
		if dummyMode {
			statssubmitter, err = util.MakeDummySubmitter()
			if err != nil {
				log.Fatal(err)
			}
		} else {
			metricsSubmissionURL := viper.GetString("metrics.submission-url")
			metricsSubmissionExchange := viper.GetString("metrics.submission-exchange")
			statssubmitter, err = util.MakeAMQPSubmitterWithReconnector(metricsSubmissionURL,
				metricsSubmissionExchange,
				verbose, func(amqpURI string) (wabbit.Conn, error) {
					conn, err := amqp.Dial(amqpURI)
					if err != nil {
						return nil, err
					}
					return conn, err
				})
			if err != nil {
				log.Fatal(err)
			}
		}
		// create InfluxDB line protocol encoder/submitter
		pse = util.MakePerformanceStatsEncoder(statssubmitter, 10*time.Second,
			dummyMode)
	}

	// create dispatcher
	dispatcher = processing.MakeHandlerDispatcher(eventChan)
	if pse != nil {
		dispatcher.SubmitStats(pse)
	}
	dispatcher.Run()
	defer func() {
		c := make(chan bool)
		dispatcher.Stop(c)
		<-c
	}()

	// create event type counter
	if enableMetrics {
		evp, err := processing.MakeEventProfiler(10*time.Second, statssubmitter)
		if err != nil {
			log.Fatal(err)

		}
		dispatcher.RegisterHandler(evp)
		evp.Run()
		defer func() {
			c := make(chan bool)
			evp.Stop(c)
			<-c
		}()
	}

	// Configure forwarding
	outputSocket := viper.GetString("output.socket")
	forward = (outputSocket != "")
	eventTypes := viper.GetStringSlice("forward.types")
	allTypes := viper.GetBool("forward.all")
	util.PrepareEventFilter(eventTypes, allTypes)

	// Optional profiling
	profileFile := viper.GetString("profile")
	if profileFile != "" {
		var f io.Writer
		f, err = os.Create(profileFile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	// Set up database writing components
	DBenabled := viper.GetBool("database.enable")
	chunkSize := viper.GetInt("chunksize")
	if DBenabled {
		dbUseMongo := viper.GetBool("database.mongo")
		dbHost := viper.GetString("database.host")
		dbDatabase := viper.GetString("database.database")
		dbUser := viper.GetString("database.user")
		dbPassword := viper.GetString("database.password")
		maxTableSize := viper.GetInt64("database.maxtablesize")
		if dbUseMongo {
			s = db.MakeMongoSlurper(dbHost, dbDatabase, dbUser, dbPassword, int(chunkSize), int64(maxTableSize))
		} else {
			rotationInterval := viper.GetDuration("database.rotate")
			s = db.MakePostgresSlurper(dbHost, dbDatabase, dbUser, dbPassword, rotationInterval, int64(maxTableSize),
				int(chunkSize))
		}
	} else {
		if verbose {
			log.Println("database not in use")
		}
		s = &db.DummySlurper{}
	}
	s.Run(eventChan)

	var forwardHandler processing.Handler
	reconnectTimes := viper.GetInt("reconnect-retries")
	// start forwarding
	if forward {
		forwardHandler = processing.MakeForwardHandler(int(reconnectTimes), outputSocket)
		if pse != nil {
			forwardHandler.(*processing.ForwardHandler).SubmitStats(pse)
		}
		rdns := viper.GetBool("active.rdns")
		if rdns {
			expiryPeriod := viper.GetDuration("active.rdns-cache-expiry")
			forwardHandler.(*processing.ForwardHandler).EnableRDNS(expiryPeriod)
			privateOnly := viper.GetBool("active.rdns-private-only")
			if privateOnly {
				forwardHandler.(*processing.ForwardHandler).RDNSHandler.EnableOnlyPrivateIPRanges()
			}
		}
		forwardHandler.(*processing.ForwardHandler).Run()
		defer func() {
			c := make(chan bool)
			forwardHandler.(*processing.ForwardHandler).Stop(c)
			<-c
		}()
	} else {
		// in this case we use a void handler that does nothing
		forwardHandler = processing.MakeVoidHandler()
	}
	dispatcher.RegisterHandler(forwardHandler)

	// Bloom filter setup
	bloomFilePath := viper.GetString("bloom.file")
	bloomAlertPrefix := viper.GetString("bloom.alert-prefix")
	bloomCompressed := viper.GetBool("bloom.zipped")
	bloomBlacklist := viper.GetStringSlice("bloom.blacklist-iocs")
	var bloomHandler *processing.BloomHandler
	if bloomFilePath != "" {
		bloomHandler, err = processing.MakeBloomHandlerFromFile(bloomFilePath,
			bloomCompressed, eventChan, forwardHandler, bloomAlertPrefix,
			bloomBlacklist)
		if err != nil {
			log.Fatal(err)
		}
		dispatcher.RegisterHandler(bloomHandler)
	}

	ipFilePath := viper.GetString("ip.blacklist")
	ipAlertPrefix := viper.GetString("ip.alert-prefix")
	var ipHandler *processing.IPHandler
	if ipFilePath != "" {
		ipHandler, err = processing.MakeIPHandlerFromFile(ipFilePath, eventChan, forwardHandler, ipAlertPrefix)
		if err != nil {
			log.Fatal(err)
		}
		dispatcher.RegisterHandler(ipHandler)
	}

	// flow aggregation setup
	flushPeriod := viper.GetDuration("flushtime")
	log.Debugf("flushtime set to %v", flushPeriod)
	fa := processing.MakeFlowAggregator(flushPeriod, eventChan)
	if pse != nil {
		fa.SubmitStats(pse)
	}
	dispatcher.RegisterHandler(fa)
	fa.Run()
	defer func() {
		c := make(chan bool)
		fa.Stop(c)
		<-c
	}()

	// DNS aggregation setup
	da := processing.MakeDNSAggregator(flushPeriod, eventChan)
	if pse != nil {
		da.SubmitStats(pse)
	}
	dispatcher.RegisterHandler(da)
	da.Run()
	defer func() {
		c := make(chan bool)
		da.Stop(c)
		<-c
	}()

	// context collector setup
	enableContext := viper.GetBool("context.enable")
	if enableContext {
		var csubmitter util.StatsSubmitter
		if dummyMode {
			csubmitter, err = util.MakeDummySubmitter()
			if err != nil {
				log.Fatal(err)
			}
		} else {
			cSubmissionURL := viper.GetString("context.submission-url")
			cSubmissionExchange := viper.GetString("context.submission-exchange")
			csubmitter, err = util.MakeAMQPSubmitter(cSubmissionURL,
				cSubmissionExchange, verbose)
			if err != nil {
				log.Fatal(err)
			}
			csubmitter.UseCompression()
			defer csubmitter.Finish()
		}
		cshp := processing.ContextShipperAMQP{}
		shipChan, err := cshp.Start(csubmitter)
		if err != nil {
			log.Fatal(err)
		}

		processing.GlobalContextCollector = processing.MakeContextCollector(
			func(entries processing.Context, logger *log.Entry) error {
				shipChan <- entries
				return nil
			},
			viper.GetDuration("context.cache-timeout"),
		)
		dispatcher.RegisterHandler(processing.GlobalContextCollector)
		if pse != nil {
			processing.GlobalContextCollector.SubmitStats(pse)
		}
		processing.GlobalContextCollector.Run()
		defer func() {
			c := make(chan bool)
			processing.GlobalContextCollector.Stop(c)
			<-c
		}()
	}

	// passive DNS setup
	enablePDNS := viper.GetBool("pdns.enable")
	if enablePDNS {
		var pdcsubmitter util.StatsSubmitter
		if dummyMode {
			pdcsubmitter, err = util.MakeDummySubmitter()
			if err != nil {
				log.Fatal(err)
			}
		} else {
			pdnsSubmissionURL := viper.GetString("pdns.submission-url")
			pdnsSubmissionExchange := viper.GetString("pdns.submission-exchange")
			pdcsubmitter, err = util.MakeAMQPSubmitter(pdnsSubmissionURL,
				pdnsSubmissionExchange, verbose)
			if err != nil {
				log.Fatal(err)
			}
			pdcsubmitter.UseCompression()
			defer pdcsubmitter.Finish()
		}
		pdc, err := processing.MakePDNSCollector(flushPeriod, pdcsubmitter)
		if err != nil {
			log.Fatal(err)
		}
		dispatcher.RegisterHandler(pdc)
		pdc.Run()
		defer func() {
			c := make(chan bool)
			pdc.Stop(c)
			<-c
		}()
	} else {
		log.Info("passive DNS collection disabled")
	}

	noCompressMsg := viper.GetBool("flowreport.nocompress")

	// Aggregate stats reporting setup
	unicornSleep := viper.GetDuration("flowreport.interval")
	if unicornSleep > 0 {
		var submitter util.StatsSubmitter
		if dummyMode {
			submitter, err = util.MakeDummySubmitter()
			if err != nil {
				log.Fatal(err)
			}
		} else {
			unicornSubmissionURL := viper.GetString("flowreport.submission-url")
			unicornSubmissionExchange := viper.GetString("flowreport.submission-exchange")
			submitter, err = util.MakeAMQPSubmitter(unicornSubmissionURL,
				unicornSubmissionExchange, verbose)
			if err != nil {
				log.Fatal(err)
			}
			defer submitter.Finish()
		}

		if !noCompressMsg {
			submitter.UseCompression()
			log.WithFields(log.Fields{
				"domain": "aggregate",
				"state":  "enabled",
			}).Info("compression of flow stats")
		} else {
			log.WithFields(log.Fields{
				"domain": "aggregate",
				"state":  "disabled",
			}).Info("compression of flow stats")
		}
		ua := processing.MakeUnicornAggregator(submitter, unicornSleep, dummyMode)
		dispatcher.RegisterHandler(ua)
		ua.Run()
		defer func() {
			c := make(chan bool)
			ua.Stop(c)
			<-c
		}()
	} else {
		log.WithFields(log.Fields{
			"domain": "aggregate",
		}).Info("flow stats reporting disabled")
	}

	// Flow extraction
	extractFlows := viper.GetBool("flowextract.enable")
	if extractFlows {
		var submitter util.StatsSubmitter
		if dummyMode {
			submitter, err = util.MakeDummySubmitter()
			if err != nil {
				log.Fatal(err)
			}
		} else {
			flowSubmissionURL := viper.GetString("flowextract.submission-url")
			flowSubmissionExchange := viper.GetString("flowextract.submission-exchange")
			submitter, err = util.MakeAMQPSubmitter(flowSubmissionURL,
				flowSubmissionExchange, verbose)
			if err != nil {
				log.Fatal(err)
			}
			defer submitter.Finish()
		}

		if noCompressMsg {
			submitter.UseCompression()
			log.WithFields(log.Fields{
				"domain": "flow-extraction",
				"state":  "enabled",
			}).Info("compression of flows")
		} else {
			log.WithFields(log.Fields{
				"domain": "flow-extraction",
				"state":  "disabled",
			}).Info("no compression of flows")
		}

		flushCount := viper.GetInt("flushcount")
		flowBloomFilePath := viper.GetString("flowextract-bloom-selector")

		ua, err := processing.MakeFlowExtractor(flushPeriod,
			int(flushCount), flowBloomFilePath,
			submitter)
		if err != nil {
			log.Fatal(err)
		}

		dispatcher.RegisterHandler(ua)
		ua.Run()
		defer func() {
			c := make(chan bool)
			ua.Stop(c)
			<-c
		}()
	} else {
		log.WithFields(log.Fields{
			"domain": "flow-extraction",
		}).Info("Flow extraction disabled")
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGUSR1)
	go func() {
		for sig := range c {
			if sig == syscall.SIGTERM || sig == syscall.SIGINT {
				pprof.StopCPUProfile()
				if submitter != nil {
					submitter.Finish()
				}
				if s != nil {
					s.Finish()
				}
				log.WithFields(log.Fields{
					"domain": "main",
				}).Println("received SIGTERM, terminating")
				inputSocket := viper.GetString("input.socket")
				_, myerr := os.Stat(inputSocket)
				if myerr == nil {
					os.Remove(inputSocket)
				}
				os.Exit(1)
			} else if sig == syscall.SIGUSR1 {
				if bloomHandler != nil {
					err := bloomHandler.Reload()
					if err != nil {
						log.Warnf("reloading of Bloom filter failed: %s", err.Error())
					} else {
						log.Info("reloading of Bloom complete")
					}
				}
			}
		}
	}()

	// create input
	inputChan := make(chan types.Entry)
	var sinput input.Input
	inputRedis := viper.GetString("input.redis.server")
	noUseRedisPipeline := viper.GetBool("input.redis.nopipe")
	if len(inputRedis) > 0 {
		sinput, err = input.MakeRedisInput(inputRedis, inputChan, int(chunkSize))
		sinput.(*input.RedisInput).UsePipelining = !noUseRedisPipeline
		sinput.(*input.RedisInput).SubmitStats(pse)
	} else {
		inputSocket := viper.GetString("input.socket")
		sinput, err = input.MakeSocketInput(inputSocket, inputChan)
	}
	if err != nil {
		log.Fatal(err)
	}
	log.WithFields(log.Fields{
		"input": sinput.GetName(),
	}).Info("selected input driver")

	sinput.SetVerbose(verbose)
	sinput.Run()
	defer func() {
		c := make(chan bool)
		sinput.Stop(c)
		<-c
	}()
	for v := range inputChan {
		dispatcher.Dispatch(&v)
	}
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "start FEVER service",
	Long: `The 'run' command starts the FEVER service, consuming events from
the input and executing all processing components.`,
	Run: mainfunc,
}

func init() {
	rootCmd.AddCommand(runCmd)

	// Input options
	runCmd.PersistentFlags().StringP("in-socket", "i", "/tmp/suri.sock", "filename of input socket (accepts EVE JSON)")
	viper.BindPFlag("input.socket", runCmd.PersistentFlags().Lookup("in-socket"))
	runCmd.PersistentFlags().StringP("in-redis", "r", "", "Redis input server (assumes \"suricata\" list key, no pwd)")
	viper.BindPFlag("input.redis.server", runCmd.PersistentFlags().Lookup("in-redis"))
	runCmd.PersistentFlags().BoolP("in-redis-nopipe", "", false, "do not use Redis pipelining")
	viper.BindPFlag("input.redis.nopipe", runCmd.PersistentFlags().Lookup("in-redis-nopipe"))

	// Output options
	runCmd.PersistentFlags().StringP("out-socket", "o", "/tmp/suri-forward.sock", "path to output socket (to forwarder), empty string disables forwarding")
	viper.BindPFlag("output.socket", runCmd.PersistentFlags().Lookup("out-socket"))

	// Forwarding options
	runCmd.PersistentFlags().StringSliceP("fwd-event-types", "t", []string{"alert", "stats"}, "event types to forward to socket")
	viper.BindPFlag("forward.types", runCmd.PersistentFlags().Lookup("fwd-event-types"))
	runCmd.PersistentFlags().BoolP("fwd-all-types", "T", false, "forward all event types")
	viper.BindPFlag("forward.all", runCmd.PersistentFlags().Lookup("fwd-all-types"))

	// Misc options
	runCmd.PersistentFlags().StringP("profile", "", "", "enable runtime profiling to given file")
	viper.BindPFlag("profile", runCmd.PersistentFlags().Lookup("profile"))
	runCmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose logging (debug log level)")
	viper.BindPFlag("verbose", runCmd.PersistentFlags().Lookup("verbose"))
	runCmd.PersistentFlags().UintP("chunksize", "c", 50000, "chunk size for batched event handling (e.g. inserts)")
	viper.BindPFlag("chunksize", runCmd.PersistentFlags().Lookup("chunksize"))
	runCmd.PersistentFlags().BoolP("dummy", "", false, "log locally instead of sending home")
	viper.BindPFlag("dummy", runCmd.PersistentFlags().Lookup("dummy"))
	runCmd.PersistentFlags().UintP("reconnect-retries", "", 0, "number of retries connecting to socket or sink, 0 = no retry limit")
	viper.BindPFlag("reconnect-retries", runCmd.PersistentFlags().Lookup("reconnect-retries"))
	runCmd.PersistentFlags().DurationP("flushtime", "f", 1*time.Minute, "time interval for event aggregation")
	viper.BindPFlag("flushtime", runCmd.PersistentFlags().Lookup("flushtime"))
	runCmd.PersistentFlags().UintP("flushcount", "", 100000, "maximum number of events in one batch (e.g. for flow extraction)")
	viper.BindPFlag("flushcount", runCmd.PersistentFlags().Lookup("flushcount"))
	runCmd.PersistentFlags().StringP("toolname", "", "fever", "set toolname")
	viper.BindPFlag("toolname", runCmd.PersistentFlags().Lookup("toolname"))

	// Database options
	runCmd.PersistentFlags().BoolP("db-enable", "", false, "write events to database")
	viper.BindPFlag("database.enable", runCmd.PersistentFlags().Lookup("db-enable"))
	runCmd.PersistentFlags().StringP("db-host", "s", "localhost:5432", "database host")
	viper.BindPFlag("database.host", runCmd.PersistentFlags().Lookup("db-host"))
	runCmd.PersistentFlags().StringP("db-user", "u", "sensor", "database user")
	viper.BindPFlag("database.user", runCmd.PersistentFlags().Lookup("db-user"))
	runCmd.PersistentFlags().StringP("db-database", "d", "events", "database DB")
	viper.BindPFlag("database.database", runCmd.PersistentFlags().Lookup("db-database"))
	runCmd.PersistentFlags().StringP("db-password", "p", "sensor", "database password")
	viper.BindPFlag("database.password", runCmd.PersistentFlags().Lookup("db-password"))
	runCmd.PersistentFlags().BoolP("db-mongo", "m", false, "use MongoDB")
	viper.BindPFlag("database.mongo", runCmd.PersistentFlags().Lookup("db-mongo"))
	runCmd.PersistentFlags().DurationP("db-rotate", "", 1*time.Hour, "time interval for database table rotations")
	viper.BindPFlag("database.rotate", runCmd.PersistentFlags().Lookup("db-rotate"))
	runCmd.PersistentFlags().Uint64P("db-maxtablesize", "", 500, "Maximum allowed cumulative table size in GB")
	viper.BindPFlag("database.maxtablesize", runCmd.PersistentFlags().Lookup("db-maxtablesize"))

	// Flow report options
	runCmd.PersistentFlags().BoolP("flowreport-nocompress", "", false, "send uncompressed flow reports (default is gzip)")
	viper.BindPFlag("flowreport.nocompress", runCmd.PersistentFlags().Lookup("flowreport-nocompress"))
	runCmd.PersistentFlags().StringP("flowreport-submission-url", "", "amqp://guest:guest@localhost:5672/", "URL to which flow reports will be submitted")
	viper.BindPFlag("flowreport.submission-url", runCmd.PersistentFlags().Lookup("flowreport-submission-url"))
	runCmd.PersistentFlags().StringP("flowreport-submission-exchange", "", "aggregations", "Exchange to which flow reports will be submitted")
	viper.BindPFlag("flowreport.submission-exchange", runCmd.PersistentFlags().Lookup("flowreport-submission-exchange"))
	runCmd.PersistentFlags().DurationP("flowreport-interval", "n", 0, "time interval for report submissions")
	viper.BindPFlag("flowreport.interval", runCmd.PersistentFlags().Lookup("flowreport-interval"))

	// Metrics submission options
	runCmd.PersistentFlags().BoolP("metrics-enable", "", false, "submit performance metrics to central sink")
	viper.BindPFlag("metrics.enable", runCmd.PersistentFlags().Lookup("metrics-enable"))
	runCmd.PersistentFlags().StringP("metrics-submission-url", "", "amqp://guest:guest@localhost:5672/", "URL to which metrics will be submitted")
	viper.BindPFlag("metrics.submission-url", runCmd.PersistentFlags().Lookup("metrics-submission-url"))
	runCmd.PersistentFlags().StringP("metrics-submission-exchange", "", "metrics", "Exchange to which metrics will be submitted")
	viper.BindPFlag("metrics.submission-exchange", runCmd.PersistentFlags().Lookup("metrics-submission-exchange"))

	// Passive DNS options
	runCmd.PersistentFlags().BoolP("pdns-enable", "", false, "collect and forward aggregated passive DNS data")
	viper.BindPFlag("pdns.enable", runCmd.PersistentFlags().Lookup("pdns-enable"))
	runCmd.PersistentFlags().StringP("pdns-submission-url", "", "amqp://guest:guest@localhost:5672/", "URL to which passive DNS events will be submitted")
	viper.BindPFlag("pdns.submission-url", runCmd.PersistentFlags().Lookup("pdns-submission-url"))
	runCmd.PersistentFlags().StringP("pdns-submission-exchange", "", "pdns", "Exchange to which passive DNS events will be submitted")
	viper.BindPFlag("pdns.submission-exchange", runCmd.PersistentFlags().Lookup("pdns-submission-exchange"))

	// Context collection options
	runCmd.PersistentFlags().BoolP("context-enable", "", false, "collect and forward flow context for alerted flows")
	viper.BindPFlag("context.enable", runCmd.PersistentFlags().Lookup("context-enable"))
	runCmd.PersistentFlags().StringP("context-submission-url", "", "amqp://guest:guest@localhost:5672/", "URL to which flow context will be submitted")
	viper.BindPFlag("context.submission-url", runCmd.PersistentFlags().Lookup("context-submission-url"))
	runCmd.PersistentFlags().StringP("context-submission-exchange", "", "context", "Exchange to which flow context events will be submitted")
	viper.BindPFlag("context.submission-exchange", runCmd.PersistentFlags().Lookup("context-submission-exchange"))
	runCmd.PersistentFlags().DurationP("context-cache-timeout", "", 60*time.Minute, "time for flow metadata to be kept for uncompleted flows")
	viper.BindPFlag("context.cache-timeout", runCmd.PersistentFlags().Lookup("context-cache-timeout"))

	// Bloom filter alerting options
	runCmd.PersistentFlags().StringP("bloom-file", "b", "", "Bloom filter for external indicator screening")
	viper.BindPFlag("bloom.file", runCmd.PersistentFlags().Lookup("bloom-file"))
	runCmd.PersistentFlags().BoolP("bloom-zipped", "z", false, "use gzipped Bloom filter file")
	viper.BindPFlag("bloom.zipped", runCmd.PersistentFlags().Lookup("bloom-zipped"))
	runCmd.PersistentFlags().StringP("bloom-alert-prefix", "", "BLF", "String prefix for Bloom filter alerts")
	viper.BindPFlag("bloom.alert-prefix", runCmd.PersistentFlags().Lookup("bloom-alert-prefix"))
	runCmd.PersistentFlags().StringSliceP("bloom-blacklist-iocs", "", []string{"/", "/index.htm", "/index.html"}, "Blacklisted strings in Bloom filter (will cause filter to be rejected)")
	viper.BindPFlag("bloom.blacklist-iocs", runCmd.PersistentFlags().Lookup("bloom-blacklist-iocs"))

	// IP blacklist alerting options
	runCmd.PersistentFlags().StringP("ip-blacklist", "", "", "List with IP ranges to alert on")
	viper.BindPFlag("ip.blacklist", runCmd.PersistentFlags().Lookup("ip-blacklist"))
	runCmd.PersistentFlags().StringP("ip-alert-prefix", "", "IP-BLACKLIST", "String prefix for IP blacklist alerts")
	viper.BindPFlag("ip.alert-prefix", runCmd.PersistentFlags().Lookup("ip-alert-prefix"))

	// Flow extraction options
	runCmd.PersistentFlags().BoolP("flowextract-enable", "", false, "extract and forward flow metadata")
	viper.BindPFlag("flowextract.enable", runCmd.PersistentFlags().Lookup("flowextract-enable"))
	runCmd.PersistentFlags().StringP("flowextract-bloom-selector", "", "", "IP address Bloom filter to select flows to extract")
	viper.BindPFlag("flowextract.bloom-selector", runCmd.PersistentFlags().Lookup("flowextract-bloom-selector"))
	runCmd.PersistentFlags().StringP("flowextract-submission-url", "", "amqp://guest:guest@localhost:5672/", "URL to which raw flow events will be submitted")
	viper.BindPFlag("flowextract.submission-url", runCmd.PersistentFlags().Lookup("flowextract-submission-url"))
	runCmd.PersistentFlags().StringP("flowextract-submission-exchange", "", "flows", "Exchange to which raw flow events will be submitted")
	viper.BindPFlag("flowextract.submission-exchange", runCmd.PersistentFlags().Lookup("flowextract-submission-exchange"))

	// Active enrichment options
	runCmd.PersistentFlags().BoolP("active-rdns", "", false, "enable active rDNS enrichment for src/dst IPs")
	viper.BindPFlag("active.rdns", runCmd.PersistentFlags().Lookup("active-rdns"))
	runCmd.PersistentFlags().DurationP("active-rdns-cache-expiry", "", 2*time.Minute, "cache expiry interval for rDNS lookups")
	viper.BindPFlag("active.rdns-cache-expiry", runCmd.PersistentFlags().Lookup("active-rdns-cache-expiry"))
	runCmd.PersistentFlags().BoolP("active-rdns-private-only", "", false, "only do active rDNS enrichment for RFC1918 IPs")
	viper.BindPFlag("active.rdns-private-only", runCmd.PersistentFlags().Lookup("active-rdns-private-only"))

	// Logging options
	runCmd.PersistentFlags().StringP("logfile", "", "", "Path to log file")
	viper.BindPFlag("logging.file", runCmd.PersistentFlags().Lookup("logfile"))
	runCmd.PersistentFlags().BoolP("logjson", "", false, "Output logs in JSON format")
	viper.BindPFlag("logging.json", runCmd.PersistentFlags().Lookup("logjson"))
}
