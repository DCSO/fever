package util

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
)

// HostNamer is a component that provides cached hostnames for IP
// addresses passed as strings.
type HostNamer struct {
	Cache *cache.Cache
	Lock  sync.Mutex
}

// NewHostNamer returns a new HostNamer with the given default expiration time.
// Data entries will be purged after each cleanupInterval.
func NewHostNamer(defaultExpiration, cleanupInterval time.Duration) *HostNamer {
	return &HostNamer{
		Cache: cache.New(defaultExpiration, cleanupInterval),
	}
}

// GetHostname returns a list of host names for a given IP address.
func (n *HostNamer) GetHostname(ipAddr string) ([]string, error) {
	n.Lock.Lock()
	defer n.Lock.Unlock()

	val, found := n.Cache.Get(ipAddr)
	if found {
		return val.([]string), nil
	}
	hns, err := net.LookupAddr(ipAddr)
	if err != nil {
		return nil, err
	}
	for i, hn := range hns {
		hns[i] = strings.TrimRight(hn, ".")
	}
	n.Cache.Set(ipAddr, hns, cache.DefaultExpiration)
	val = hns
	return val.([]string), nil
}

// Flush clears the cache of a HostNamer.
func (n *HostNamer) Flush() {
	n.Cache.Flush()
}
