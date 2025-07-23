package types

import (
	"fmt"
	"time"

	"go4.org/netipx"
)

// FirewallType are the supported firewall implementations.
type FirewallType string

// All supported firewall implementations.
const (
	FirewallMock     FirewallType = "mock"
	FirewallNFTables FirewallType = "nftables"
)

// FirewallTypeFromString returns a valid FirewallType for the given string, or
// an error if the value is invalid.
func FirewallTypeFromString(val string) (FirewallType, error) {
	switch FirewallType(val) {
	case FirewallMock:
		return FirewallMock, nil
	case FirewallNFTables:
		return FirewallNFTables, nil
	}
	return "", fmt.Errorf("unsupported firewall type '%s'", val)
}

// Firewall is the interface for managing firewall rules.
type Firewall interface {
	// Init initializes the firewall (creates tables, chains, etc.)
	Init() error

	// Allow grants access to the destination port from a set of IP addresses for
	// a specific amount of time.
	Allow(ipSet *netipx.IPSet, destPort uint16, duration time.Duration) error

	// Deny blocks access to the destination port from a set of IP addresses.
	Deny(ipSet *netipx.IPSet, destPort uint16) error
}
