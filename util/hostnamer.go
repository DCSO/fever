package util

// HostNamer is an interface specifying a component that provides
// cached hostnames for IP addresses passed as strings.
type HostNamer interface {
	GetHostname(ipAddr string) ([]string, error)
	Flush()
}
