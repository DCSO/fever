package mgmt

// DCSO FEVER
// Copyright (c) 2021, DCSO GmbH

import "github.com/DCSO/fever/processing"

// State contains references to components to be affected by RPC calls.
type State struct {
	BloomHandler *processing.BloomHandler
}
