package firewall

import (
	"fmt"
	"net/netip"

	"go4.org/netipx"
)

// ParseToIPSet parses one or more IP address strings in plain, CIDR or range
// notation, and returns an IP set containing IP ranges.
func ParseToIPSet(ipAddr ...string) (*netipx.IPSet, error) {
	var b netipx.IPSetBuilder
	for _, ip := range ipAddr {
		// Try a plain address first
		addr, err := netip.ParseAddr(ip)
		if err == nil {
			b.AddRange(netipx.IPRangeFrom(addr, addr))
			continue
		}
		// Try a prefix (CIDR) next
		cidr, err := netip.ParsePrefix(ip)
		if err == nil {
			b.AddRange(netipx.RangeOfPrefix(cidr))
			continue
		}
		// Finally try a range
		ipRange, err := netipx.ParseIPRange(ip)
		if err != nil {
			return nil, fmt.Errorf("failed parsing IP address '%s': %w", ip, err)
		}
		b.AddRange(ipRange)
	}

	ipSet, err := b.IPSet()
	if err != nil {
		return nil, fmt.Errorf("failed building IP set: %w", err)
	}

	return ipSet, nil
}
