package mgmt

// Server ...
type Server interface {
	// ListenAndServe is expected to create a listener and to block until a
	// shutdown is invoked.
	ListenAndServe() error
	Stop()
}
