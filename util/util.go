package util

// DCSO FEVER
// Copyright (c) 2017, 2018, 2020, DCSO GmbH

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/DCSO/fever/types"

	"github.com/buger/jsonparser"
)

// ToolName is a string containing the name of this software, lowercase.
var ToolName = "fever"

// ToolNameUpper is a string containing the name of this software, uppercase.
var ToolNameUpper = "FEVER"

var evekeys = [][]string{
	[]string{"event_type"},             //  0
	[]string{"src_ip"},                 //  1
	[]string{"src_port"},               //  2
	[]string{"dest_ip"},                //  3
	[]string{"dest_port"},              //  4
	[]string{"timestamp"},              //  5
	[]string{"proto"},                  //  6
	[]string{"flow", "bytes_toclient"}, //  7
	[]string{"flow", "bytes_toserver"}, //  8
	[]string{"http", "hostname"},       //  9
	[]string{"http", "url"},            // 10
	[]string{"http", "http_method"},    // 11
	[]string{"dns", "rrname"},          // 12
	[]string{"flow", "pkts_toclient"},  // 13
	[]string{"flow", "pkts_toserver"},  // 14
	[]string{"dns", "rcode"},           // 15
	[]string{"dns", "rdata"},           // 16
	[]string{"dns", "rrtype"},          // 17
	[]string{"dns", "type"},            // 18
	[]string{"tls", "sni"},             // 19
	[]string{"dns", "version"},         // 20
	[]string{"dns", "answers"},         // 21
	[]string{"flow_id"},                // 22
}

// ParseJSON extracts relevant fields from an EVE JSON entry into an Entry struct.
func ParseJSON(json []byte) (e types.Entry, parseerr error) {
	e = types.Entry{}
	jsonparser.EachKey(json, func(idx int, value []byte, vt jsonparser.ValueType,
		err error) {
		if parseerr != nil {
			return
		}
		if err != nil {
			parseerr = err
			return
		}
		switch idx {
		case 0:
			e.EventType, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = err
				return
			}
		case 1:
			e.SrcIP = string(value[:])
		case 2:
			e.SrcPort, err = jsonparser.ParseInt(value)
			if err != nil {
				parseerr = err
				return
			}
		case 3:
			e.DestIP = string(value[:])
		case 4:
			e.DestPort, err = jsonparser.ParseInt(value)
			if err != nil {
				parseerr = err
				return
			}
		case 5:
			e.Timestamp = string(value[:])
		case 6:
			e.Proto = string(value[:])
		case 7:
			e.BytesToClient, err = jsonparser.ParseInt(value)
			if err != nil {
				parseerr = err
				return
			}
		case 8:
			e.BytesToServer, err = jsonparser.ParseInt(value)
			if err != nil {
				parseerr = err
				return
			}
		case 9:
			e.HTTPHost, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = err
				return
			}
		case 10:
			e.HTTPUrl, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = err
				return
			}
		case 11:
			e.HTTPMethod, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = err
				return
			}
		case 12:
			e.DNSRRName, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = err
				return
			}
		case 13:
			e.PktsToClient, err = jsonparser.ParseInt(value)
			if err != nil {
				parseerr = err
				return
			}
		case 14:
			e.PktsToServer, err = jsonparser.ParseInt(value)
			if err != nil {
				parseerr = err
				return
			}
		case 15:
			e.DNSRCode, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = err
				return
			}
		case 16:
			e.DNSRData, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = err
				return
			}
		case 17:
			e.DNSRRType, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = err
				return
			}
		case 18:
			e.DNSType, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = err
				return
			}
		case 19:
			e.TLSSni, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = err
				return
			}
		case 20:
			e.DNSVersion, err = jsonparser.ParseInt(value)
			if err != nil {
				parseerr = err
				return
			}
		case 21:
			if e.DNSVersion == 2 {
				e.DNSAnswers = make([]types.DNSAnswer, 0)
				jsonparser.ArrayEach(value, func(mvalue []byte, dataType jsonparser.ValueType, offset int, err error) {
					var rrname, rdata, rrtype string
					var merr error
					if parseerr != nil {
						return
					}
					if err != nil {
						parseerr = err
						return
					}
					rdata, merr = jsonparser.GetString(mvalue, "rdata")
					if merr != nil {
						if merr != jsonparser.KeyPathNotFoundError {
							parseerr = merr
							return
						}
					}
					rrname, merr = jsonparser.GetString(mvalue, "rrname")
					if merr != nil {
						parseerr = merr
						return
					}
					rrtype, merr = jsonparser.GetString(mvalue, "rrtype")
					if merr != nil {
						parseerr = merr
						return
					}
					dnsa := types.DNSAnswer{
						DNSRCode:  e.DNSRCode,
						DNSRData:  rdata,
						DNSRRName: rrname,
						DNSRRType: rrtype,
					}
					e.DNSAnswers = append(e.DNSAnswers, dnsa)
				})
			}
			if err != nil {
				parseerr = err
				return
			}
		case 22:
			e.FlowID, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = err
				return
			}
		}
	}, evekeys...)
	e.JSONLine = string(json)

	return e, parseerr
}

// GetSensorID returns the machine ID of the system it is being run on, or
// the string "<no_machine_id>"" if the ID cannot be determined.
func GetSensorID() (string, error) {
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		return "<no_machine_id>", nil
	}
	b, err := ioutil.ReadFile("/etc/machine-id")
	if err != nil {
		return "<no_machine_id>", nil
	}
	return strings.TrimSpace(string(b)), nil
}

var src = rand.NewSource(time.Now().UnixNano())

// RandStringBytesMaskImprSrc returns a random string of a given length.
func RandStringBytesMaskImprSrc(n int) string {
	letterBytes := "abcdefghijk"
	letterIdxBits := uint(6)                     // 6 bits to represent a letter index
	letterIdxMask := int64(1<<letterIdxBits - 1) // All 1-bits, as many as letterIdxBits
	letterIdxMax := 63 / letterIdxBits           // # of letter indices fitting in 63 bits
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// MakeTLSConfig returns a TLS configuration suitable for an endpoint with private
// key stored in keyFile and corresponding certificate stored in certFile. rcas
// defines a list of root CA filenames.
// If certFile and keyFile are empty, e.g., when configuring a tls-client
// endpoint w/o mutual authentication, only the RootCA pool is populated.
// Note: It appears as if ICAs have to be loaded via a chained server
// certificate file as the RootCAs pool in tls.Config appears to be referred to
// for RCAs only.
func MakeTLSConfig(certFile, keyFile string, rcas []string, skipVerify bool) (*tls.Config, error) {
	certs := make([]tls.Certificate, 0, 1)

	if certFile != "" || keyFile != "" {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	rcaPool := x509.NewCertPool()
	for _, filename := range rcas {
		rca, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		rcaPool.AppendCertsFromPEM(rca)
	}

	return &tls.Config{
		Certificates:       certs,
		RootCAs:            rcaPool,
		InsecureSkipVerify: skipVerify,
	}, nil
}
