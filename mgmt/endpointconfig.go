package mgmt

// DCSO FEVER
// Copyright (c) 2021, DCSO GmbH

import (
	"crypto/tls"
	fmt "fmt"

	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

// EndpointConfig ...
type EndpointConfig struct {
	ListenerAddress string
	ServerAddress   string
	Network         string
	Params          map[string]interface{}
	TLSConfig       *tls.Config
	TLSDisable      bool
	Disable         bool
}

// GRPCEndpointConfig ...
type GRPCEndpointConfig struct {
	EndpointConfig
	ServerOptions []grpc.ServerOption
	DialOptions   []grpc.DialOption
}

// EndpointConfigFromViper creates a new GRPCEndpointConfig from the relevant
// Viper configs
func EndpointConfigFromViper() GRPCEndpointConfig {
	var mgmtCfg GRPCEndpointConfig
	host := viper.GetString("mgmt.host")
	network := viper.GetString("mgmt.network")
	socket := viper.GetString("mgmt.socket")

	if host != "" {
		mgmtCfg = GRPCEndpointConfig{
			EndpointConfig: EndpointConfig{
				Network:         network,
				ListenerAddress: host,
				ServerAddress:   host,
				TLSDisable:      true, // XXX we may choose to support TLS eventually
			},
			DialOptions: []grpc.DialOption{grpc.WithInsecure()},
		}
	} else {
		mgmtCfg = GRPCEndpointConfig{
			EndpointConfig: EndpointConfig{
				Network:         "unix",
				ListenerAddress: socket,
			},
			DialOptions: []grpc.DialOption{grpc.WithInsecure()},
		}
	}
	return mgmtCfg
}

// DialString returns a string from the given config that is suitable to be
// passed into a grpc.Dial() function.
func (e GRPCEndpointConfig) DialString() string {
	if e.EndpointConfig.Network == "unix" {
		return fmt.Sprintf("%s:%s", e.EndpointConfig.Network, e.EndpointConfig.ListenerAddress)
	}
	return fmt.Sprintf("dns:///%s", e.EndpointConfig.ListenerAddress)
}
