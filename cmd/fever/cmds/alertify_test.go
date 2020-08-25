package cmd

import (
	"bytes"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/DCSO/fever/types"
	"github.com/DCSO/fever/util"
)

func checkAlertified(t *testing.T, es []types.Entry, ioc string,
	result string) bool {
	a := makeAlertifyAlertifier("TEST")
	var buf bytes.Buffer
	for _, e := range es {
		err := emitAlertsForEvent(a, e, ioc, &buf, 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	return strings.Contains(buf.String(), result)
}

func checkLimit(t *testing.T, es []types.Entry, ioc string) {
	a := makeAlertifyAlertifier("TEST")
	var buf bytes.Buffer
	i := 0
	for _, e := range es {
		err := emitAlertsForEvent(a, e, ioc, &buf, 1)
		if i == 1 {
			if err == nil {
				t.Fatal(err)
			}
			if !strings.Contains(err.Error(), `limit reached (1)`) {
				t.Fatal("wrong limit error message: ", err.Error())
			}
		}
		i++
	}
}

func TestAlertify(t *testing.T) {
	ins, err := ioutil.ReadFile("testdata/alertify_input.json")
	if err != nil {
		t.Fatal(err)
	}

	inputs := make([]types.Entry, 0)
	for _, line := range strings.Split(string(ins), "\n") {
		e, err := util.ParseJSON([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, e)
	}

	if !checkAlertified(t, inputs, "evader.example.com",
		`TEST Possibly bad HTTP host: evader.example.com`) {
		t.Fatal("evader.example.com not processed")
	}

	if !checkAlertified(t, inputs, "static.programme-tv.net",
		`TEST Possibly bad DNS response for static.programme-tv.net`) {
		t.Fatal("static.programme-tv.net not processed")
	}

	if !checkAlertified(t, inputs, "example.com",
		`TEST Possibly bad TLS SNI: example.com`) {
		t.Fatal("example.com not processed")
	}

	if !checkAlertified(t, inputs, "/compressed/eicar.txt/ce%3Agzip,gzip;gzip;gzip",
		`TEST Possibly bad HTTP URL: GET | evader.example.com | /compressed/eicar.txt/ce%3Agzip,gzip;gzip;gzip`) {
		t.Fatal("example.com URL not processed")
	}

	checkLimit(t, inputs, "example.com")
}
