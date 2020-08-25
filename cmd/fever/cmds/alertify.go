package cmd

// DCSO FEVER
// Copyright (c) 2020, DCSO GmbH

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/DCSO/fever/input"
	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"
	log "github.com/sirupsen/logrus"

	"github.com/buger/jsonparser"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var count uint64

type alertifyAlertJSONProvider struct{}

// GetAlertJSON returns the "alert" subobject for an alert EVE event.
func (a alertifyAlertJSONProvider) GetAlertJSON(inputEvent types.Entry,
	prefix string, ioc string) ([]byte, error) {
	return util.GenericGetAlertObjForIoc(inputEvent, prefix, ioc,
		"%s Generic IoC match for: %s")
}

func makeAlertifyAlertifier(prefix string) *util.Alertifier {
	a := util.MakeAlertifier(prefix)
	a.RegisterMatchType("dns-req", util.AlertJSONProviderDNSReq{})
	a.RegisterMatchType("dns-resp", util.AlertJSONProviderDNSResp{})
	a.RegisterMatchType("tls-sni", util.AlertJSONProviderTLSSni{})
	a.RegisterMatchType("http-host", util.AlertJSONProviderHTTPHost{})
	a.RegisterMatchType("http-url", util.AlertJSONProviderHTTPURL{})
	a.RegisterMatchType("generic", alertifyAlertJSONProvider{})
	a.SetExtraModifier(func(inputAlert *types.Entry, ioc string) error {
		iocEscaped, err := util.EscapeJSON(ioc)
		if err != nil {
			return err
		}
		val, err := jsonparser.Set([]byte(inputAlert.JSONLine), iocEscaped,
			"_extra", "vast-ioc")
		if err != nil {
			return err
		}
		inputAlert.JSONLine = string(val)
		return nil
	})
	return a
}

func emitAlertsForEvent(a *util.Alertifier, e types.Entry, ioc string,
	out io.Writer, limit uint64) error {
	var err error
	var alert *types.Entry
	var specificMatch = false
	if e.TLSSni == ioc {
		specificMatch = true
		alert, err = a.MakeAlert(e, ioc, "tls-sni")
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\n", string(alert.JSONLine))
		if limit > 0 && count >= limit {
			return fmt.Errorf("limit reached (%d)", limit)
		}
		count++
	}
	if e.DNSRRName == ioc {
		specificMatch = true
		if e.DNSType == "answer" {
			alert, err = a.MakeAlert(e, ioc, "dns-resp")
		} else {
			alert, err = a.MakeAlert(e, ioc, "dns-req")
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\n", string(alert.JSONLine))
		if limit > 0 && count >= limit {
			return fmt.Errorf("limit reached (%d)", limit)
		}
		count++
	}
	if e.HTTPHost == ioc {
		specificMatch = true
		alert, err = a.MakeAlert(e, ioc, "http-host")
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\n", string(alert.JSONLine))
		if limit > 0 && count >= limit {
			return fmt.Errorf("limit reached (%d)", limit)
		}
		count++
	}
	if strings.Contains(e.HTTPUrl, ioc) {
		specificMatch = true
		alert, err = a.MakeAlert(e, ioc, "http-url")
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\n", string(alert.JSONLine))
		if limit > 0 && count >= limit {
			return fmt.Errorf("limit reached (%d)", limit)
		}
		count++
	}
	if !specificMatch {
		alert, err = a.MakeAlert(e, ioc, "generic")
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\n", string(alert.JSONLine))
		if limit > 0 && count >= limit {
			return fmt.Errorf("limit reached (%d)", limit)
		}
		count++
	}
	return nil
}

func alertify(cmd *cobra.Command, args []string) {
	eventChan := make(chan types.Entry, defaultQueueSize)

	sinput := input.MakeStdinInput(eventChan)
	sinput.Run()
	c := make(chan bool)

	prefix := viper.GetString("alert-prefix")
	ioc := viper.GetString("ioc")
	if len(ioc) == 0 {
		log.Fatal("IoC cannot be empty")
	}
	limit := viper.GetUint("alert-limit")

	a := makeAlertifyAlertifier(prefix)
	for e := range eventChan {
		err := emitAlertsForEvent(a, e, ioc, os.Stdout, uint64(limit))
		if err != nil {
			log.Error(err)
		}
	}

	sinput.Stop(c)
	<-c
}

var alertifyCmd = &cobra.Command{
	Use:   "alertify",
	Short: "convert metadata events into alerts",
	Long:  `The 'alertify' command converts all metadata events read from stdin to alert events.`,
	Run:   alertify,
}

func init() {
	rootCmd.AddCommand(alertifyCmd)

	alertifyCmd.PersistentFlags().StringP("ioc", "i", "<none>", "indicator to flag for in input event")
	viper.BindPFlag("ioc", alertifyCmd.PersistentFlags().Lookup("ioc"))
	alertifyCmd.PersistentFlags().StringP("alert-prefix", "p", "ALERTIFY", "prefix for alert.signature field")
	viper.BindPFlag("alert-prefix", alertifyCmd.PersistentFlags().Lookup("alert-prefix"))
	alertifyCmd.PersistentFlags().UintP("alert-limit", "l", 0, "limit for alerts to be created (0 = no limit)")
	viper.BindPFlag("alert-limit", alertifyCmd.PersistentFlags().Lookup("alert-limit"))
}
