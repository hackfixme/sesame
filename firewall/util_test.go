package firewall

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
)

func TestParseToIPSet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   []string
		expErr  string
		checkFn func(t *testing.T, ipSet *netipx.IPSet)
	}{
		{
			name:  "ok/single_plain_ipv4",
			input: []string{"192.168.1.1"},
			checkFn: func(t *testing.T, ipSet *netipx.IPSet) {
				addr := netip.MustParseAddr("192.168.1.1")
				assert.True(t, ipSet.Contains(addr))
				assert.False(t, ipSet.Contains(netip.MustParseAddr("192.168.1.2")))
			},
		},
		{
			name:  "ok/single_plain_ipv6",
			input: []string{"2001:db8::1"},
			checkFn: func(t *testing.T, ipSet *netipx.IPSet) {
				addr := netip.MustParseAddr("2001:db8::1")
				assert.True(t, ipSet.Contains(addr))
				assert.False(t, ipSet.Contains(netip.MustParseAddr("2001:db8::2")))
			},
		},
		{
			name:  "ok/single_cidr_ipv4",
			input: []string{"192.168.1.0/24"},
			checkFn: func(t *testing.T, ipSet *netipx.IPSet) {
				assert.True(t, ipSet.Contains(netip.MustParseAddr("192.168.1.1")))
				assert.True(t, ipSet.Contains(netip.MustParseAddr("192.168.1.255")))
				assert.False(t, ipSet.Contains(netip.MustParseAddr("192.168.2.1")))
				prefix := netip.MustParsePrefix("192.168.1.0/24")
				assert.True(t, ipSet.ContainsPrefix(prefix))
			},
		},
		{
			name:  "ok/single_cidr_ipv6",
			input: []string{"2001:db8::/32"},
			checkFn: func(t *testing.T, ipSet *netipx.IPSet) {
				assert.True(t, ipSet.Contains(netip.MustParseAddr("2001:db8::")))
				assert.True(t, ipSet.Contains(netip.MustParseAddr("2001:db8:ffff:ffff::")))
				assert.False(t, ipSet.Contains(netip.MustParseAddr("2001:db9::")))
				prefix := netip.MustParsePrefix("2001:db8::/32")
				assert.True(t, ipSet.ContainsPrefix(prefix))
			},
		},
		{
			name:  "ok/single_range_ipv4",
			input: []string{"192.168.1.1-192.168.1.10"},
			checkFn: func(t *testing.T, ipSet *netipx.IPSet) {
				assert.True(t, ipSet.Contains(netip.MustParseAddr("192.168.1.1")))
				assert.True(t, ipSet.Contains(netip.MustParseAddr("192.168.1.5")))
				assert.True(t, ipSet.Contains(netip.MustParseAddr("192.168.1.10")))
				assert.False(t, ipSet.Contains(netip.MustParseAddr("192.168.1.11")))
				ipRange := netipx.IPRangeFrom(
					netip.MustParseAddr("192.168.1.1"),
					netip.MustParseAddr("192.168.1.10"))
				assert.True(t, ipSet.ContainsRange(ipRange))
			},
		},
		{
			name:  "ok/single_range_ipv6",
			input: []string{"2001:db8::1-2001:db8::10"},
			checkFn: func(t *testing.T, ipSet *netipx.IPSet) {
				assert.True(t, ipSet.Contains(netip.MustParseAddr("2001:db8::1")))
				assert.True(t, ipSet.Contains(netip.MustParseAddr("2001:db8::5")))
				assert.True(t, ipSet.Contains(netip.MustParseAddr("2001:db8::10")))
				assert.False(t, ipSet.Contains(netip.MustParseAddr("2001:db8::11")))
			},
		},
		{
			name:  "ok/multiple_mixed",
			input: []string{"192.168.1.1", "10.0.0.0/8", "172.16.1.1-172.16.1.100"},
			checkFn: func(t *testing.T, ipSet *netipx.IPSet) {
				assert.True(t, ipSet.Contains(netip.MustParseAddr("192.168.1.1")))
				assert.True(t, ipSet.Contains(netip.MustParseAddr("10.5.5.5")))
				assert.True(t, ipSet.Contains(netip.MustParseAddr("172.16.1.50")))
				assert.False(t, ipSet.Contains(netip.MustParseAddr("8.8.8.8")))
			},
		},
		{
			name:  "ok/empty_input",
			input: []string{},
			checkFn: func(t *testing.T, ipSet *netipx.IPSet) {
				assert.False(t, ipSet.Contains(netip.MustParseAddr("192.168.1.1")))
				assert.Equal(t, 0, len(ipSet.Ranges()))
			},
		},
		{
			name:  "ok/mixed_ipv4_ipv6",
			input: []string{"192.168.1.1", "2001:db8::1/128"},
			checkFn: func(t *testing.T, ipSet *netipx.IPSet) {
				assert.True(t, ipSet.Contains(netip.MustParseAddr("192.168.1.1")))
				assert.True(t, ipSet.Contains(netip.MustParseAddr("2001:db8::1")))
				assert.False(t, ipSet.Contains(netip.MustParseAddr("192.168.1.2")))
				assert.False(t, ipSet.Contains(netip.MustParseAddr("2001:db8::2")))
			},
		},
		{
			name:   "err/invalid_ip_address",
			input:  []string{"not.an.ip"},
			expErr: "failed parsing IP address",
		},
		{
			name:   "err/invalid_cidr",
			input:  []string{"192.168.1.1/33"},
			expErr: "failed parsing IP address",
		},
		{
			name:   "err/invalid_range",
			input:  []string{"192.168.1.10-192.168.1.1"},
			expErr: "failed parsing IP address",
		},
		{
			name:   "err/malformed_range",
			input:  []string{"192.168.1.1-"},
			expErr: "failed parsing IP address",
		},
		{
			name:   "err/mixed_valid_invalid",
			input:  []string{"192.168.1.1", "invalid"},
			expErr: "failed parsing IP address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := ParseToIPSet(tt.input...)

			if tt.expErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expErr)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
				assert.IsType(t, &netipx.IPSet{}, result)

				if tt.checkFn != nil {
					tt.checkFn(t, result)
				}
			}
		})
	}
}
