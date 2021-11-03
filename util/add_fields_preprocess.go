package util

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

// PreprocessAddedFields preprocesses the added fields to be able to only use
// fast string operations to add them to JSON text later. This code
// progressively builds a JSON snippet by adding JSON key-value pairs for each
// added field, e.g. `, "foo":"bar"`.
func PreprocessAddedFields(fields map[string]string) (string, error) {
	j := ""
	for k, v := range fields {
		// Escape the fields to make sure we do not mess up the JSON when
		// encountering weird symbols in field names or values.
		kval, err := EscapeJSON(k)
		if err != nil {
			log.Warningf("cannot escape value: %s", v)
			return "", err
		}
		vval, err := EscapeJSON(v)
		if err != nil {
			log.Warningf("cannot escape value: %s", v)
			return "", err
		}
		j += fmt.Sprintf(",%s:%s", kval, vval)
	}
	// We finish the list of key-value pairs with a final brace:
	// `, "foo":"bar"}`. This string can now just replace the final brace in a
	// given JSON string. If there were no added fields, we just leave the
	// output at the final brace.
	j += "}"
	return j, nil
}
