package models

import (
	"time"

	"go4.org/netipx"
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

	// Allow grants the given IP address range access to the port for a specific
	// duration.
	Allow(ipRange netipx.IPRange, destPort uint16, duration time.Duration) error
}

// FirewallManager is the interface for managing access of client IPs to services.
type FirewallManager interface {
	// AllowAccess grants access of client IP ranges in the set to a service for a
	// specific duration.
	AllowAccess(ipSet *netipx.IPSet, serviceName string, duration time.Duration) error
}
