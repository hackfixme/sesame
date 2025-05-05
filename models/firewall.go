package models

import (
	"net/netip"
	"time"
)

// FirewallType are the supported firewall implementations.
type FirewallType string

const (
	FirewallMock     FirewallType = "mock"
	FirewallNFTables FirewallType = "nftables"
)

// Firewall is the interface for managing firewall rules.
type Firewall interface {
	// Setup initializes the firewall (creates tables, chains, etc.)
	Setup() error

	// Allows the given IP address access to the port for a specific duration.
	Allow(srcIP netip.Addr, destPort uint16, duration time.Duration) error
}

// FirewallManager is the interface for managing access of client IPs to services.
type FirewallManager interface {
	// AllowAccess allows access of a client to a service for a specific duration.
	AllowAccess(clientIP netip.Addr, serviceName string, duration time.Duration) error
}
