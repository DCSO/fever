package util

// DCSO FEVER
// Copyright (c) 2017, 2023, DCSO GmbH

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"

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
	[]string{"in_iface"},               // 23
	[]string{"app_proto"},              // 24
	[]string{"tls", "fingerprint"},     // 25
}

// EscapeJSON escapes a string as a quoted byte slice for direct use in jsonparser.Set().
func EscapeJSON(i string) ([]byte, error) {
	b, err := json.Marshal(i)
	if err != nil {
		return []byte(""), err
	}
	return b, nil
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
			parseerr = fmt.Errorf("%d: %w", idx, err)
			return
		}
		// skip null fields; these will not be handled by the low-level
		// jsonparser.Parse* () functions
		if bytes.Equal(value, []byte("null")) {
			return
		}
		switch idx {
		case 0:
			e.EventType, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 1:
			e.SrcIP = string(value[:])
		case 2:
			e.SrcPort, err = jsonparser.ParseInt(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 3:
			e.DestIP = string(value[:])
		case 4:
			e.DestPort, err = jsonparser.ParseInt(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 5:
			e.Timestamp = string(value[:])
		case 6:
			e.Proto = string(value[:])
		case 7:
			e.BytesToClient, err = jsonparser.ParseInt(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 8:
			e.BytesToServer, err = jsonparser.ParseInt(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 9:
			e.HTTPHost, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 10:
			e.HTTPUrl, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 11:
			e.HTTPMethod, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 12:
			e.DNSRRName, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 13:
			e.PktsToClient, err = jsonparser.ParseInt(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 14:
			e.PktsToServer, err = jsonparser.ParseInt(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 15:
			e.DNSRCode, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 16:
			e.DNSRData, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 17:
			e.DNSRRType, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 18:
			e.DNSType, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 19:
			e.TLSSNI, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 20:
			e.DNSVersion, err = jsonparser.ParseInt(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
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
						parseerr = fmt.Errorf("%d: %w", idx, err)
						return
					}
					if bytes.Equal(mvalue, []byte("null")) {
						return
					}
					rdata, merr = jsonparser.GetString(mvalue, "rdata")
					if merr != nil {
						if merr != jsonparser.KeyPathNotFoundError {
							// We do not want to report errors caused by the
							// parser not being able to parse "null" values.
							// In this case it would report the message
							// "Value is not a string: null".
							if !strings.Contains(merr.Error(), "null") {
								parseerr = merr
								return
							}
						}
					}
					rrname, merr = jsonparser.GetString(mvalue, "rrname")
					if merr != nil {
						if merr != jsonparser.KeyPathNotFoundError {
							// See above.
							if !strings.Contains(merr.Error(), "null") {
								parseerr = merr
								return
							}
						}
					}
					rrtype, merr = jsonparser.GetString(mvalue, "rrtype")
					if merr != nil {
						if merr != jsonparser.KeyPathNotFoundError {
							// See above.
							if !strings.Contains(merr.Error(), "null") {
								parseerr = merr
								return
							}
						}
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
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 22:
			e.FlowID, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 23:
			e.Iface, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 24:
			e.AppProto, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
				return
			}
		case 25:
			e.TLSFingerprint, err = jsonparser.ParseString(value)
			if err != nil {
				parseerr = fmt.Errorf("%d: %w", idx, err)
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

// RndStringFromRunes returns a string of length n
// with randomly picked runes from fromRunes slice
func RndStringFromRunes(fromRunes []rune, n int) string {
	result := make([]rune, n)
	numRunes := len(fromRunes)
	for i := range result {
		result[i] = fromRunes[rand.Intn(numRunes)]
	}
	return string(result)
}

// RndStringFromBytes returns a string of length n
// with randomly picked bytes from fromBytes slice
func RndStringFromBytes(fromBytes []byte, n int) string {
	result := make([]byte, n)
	numBytes := len(fromBytes)
	for i := range result {
		result[i] = fromBytes[rand.Intn(numBytes)]
	}
	return string(result)
}

// RndStringFromAlpha returns a string of length n
// with randomly picked alphabetic characters
func RndStringFromAlpha(n int) string {
	return RndStringFromBytes([]byte("abcdefghijklmnopqrstuvwxyz"), n)
}

// RndHexString returns a Hex string of length n
func RndHexString(n int) string {
	return RndStringFromBytes([]byte("0123456789abcdef"), n)
}

// RndTLSFingerprint returns a random string in
// the form of a TLS fingerprint
func RndTLSFingerprint() string {
	nums := make([]string, 20)
	for i := 0; i < 20; i++ {
		nums[i] = RndHexString(2)
	}
	return strings.Join(nums, ":")
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

	if certFile != "" && keyFile != "" {
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
