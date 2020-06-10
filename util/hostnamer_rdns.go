package util

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
)

// HostNamerRDNS is a component that provides cached hostnames for IP
// addresses passed as strings, determined via reverse DNS lookups.
type HostNamerRDNS struct {
	cache *cache.Cache
	lock  sync.Mutex
}

// NewHostNamerRDNS returns a new HostNamer with the given default expiration time.
// Data entries will be purged after each cleanupInterval.
func NewHostNamerRDNS(defaultExpiration, cleanupInterval time.Duration) *HostNamerRDNS {
	return &HostNamerRDNS{
		cache: cache.New(defaultExpiration, cleanupInterval),
	}
}

// GetHostname returns a list of host names for a given IP address.
func (n *HostNamerRDNS) GetHostname(ipAddr string) ([]string, error) {
	n.lock.Lock()
	defer n.lock.Unlock()

	val, found := n.cache.Get(ipAddr)
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
	n.cache.Set(ipAddr, hns, cache.DefaultExpiration)
	val = hns
	return val.([]string), nil
}

// Flush clears the cache of a HostNamerRDNS.
func (n *HostNamerRDNS) Flush() {
	n.cache.Flush()
}
