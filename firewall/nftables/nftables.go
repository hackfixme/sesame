package nftables

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"go.hackfix.me/sesame/models"
)

const (
	tableName = "sesame"
	chainName = "input"
)

// NFTables is an abstraction over the Linux nftables firewall.
type NFTables struct {
	conn  *gnft.Conn
	table *gnft.Table
	// Dynamic IPv4/6 sets for allowed source address and destination port pairs.
	allowedSet4 *gnft.Set
	allowedSet6 *gnft.Set
	logger      *slog.Logger
}

var _ models.Firewall = &NFTables{}

// New returns a new NFTables instance.
func New(logger *slog.Logger) *NFTables {
	return &NFTables{
		conn:   &gnft.Conn{},
		logger: logger.With("component", "nftables"),
	}
}

// Setup initializes the firewall.
//
// It creates the following ruleset:
//
//	table inet sesame {
//	    set allowed_clients {
//	        type ipv4_addr . inet_service
//	        flags dynamic,timeout
//	        timeout 5m
//	    }
//
//	    set allowed_clients6 {
//	        type ipv6_addr . inet_service
//	        flags dynamic,timeout
//	        timeout 5m
//	    }
//
//	    chain input {
//	        type filter hook input priority filter; policy drop;
//	        meta mark 0x00000001 accept
//	        ct state established,related accept
//	        ip saddr . tcp dport @allowed_clients accept
//	        ip6 saddr . tcp dport @allowed_clients6 accept
//	    }
//	}
func (n *NFTables) Setup() error {
	n.logger.Debug("starting setup")

	// Create the sesame table
	// table inet sesame {}
	table := &gnft.Table{
		Name:   tableName,
		Family: gnft.TableFamilyINet,
	}
	n.conn.AddTable(table)

	// Create IPv4 and IPv6 sets, whose elements are concatenations of the source
	// IP address and the destination port.
	// set allowed_clients {
	//     type ipv4_addr . inet_service
	//     flags dynamic,timeout
	//     timeout 5m
	// }
	n.allowedSet4 = &gnft.Set{
		ID:            1,
		Name:          "allowed_clients",
		Table:         table,
		KeyType:       gnft.MustConcatSetType(gnft.TypeIPAddr, gnft.TypeInetService),
		Concatenation: true,
		Dynamic:       true,
		HasTimeout:    true,
		Timeout:       5 * time.Minute,
	}
	if err := n.conn.AddSet(n.allowedSet4, nil); err != nil {
		return fmt.Errorf("failed adding IPv4 set: %w", err)
	}

	// set allowed_clients6 {
	//     type ipv6_addr . inet_service
	//     flags dynamic,timeout
	//     timeout 5m
	// }
	n.allowedSet6 = &gnft.Set{
		ID:            2,
		Name:          "allowed_clients6",
		Table:         table,
		KeyType:       gnft.MustConcatSetType(gnft.TypeIP6Addr, gnft.TypeInetService),
		Concatenation: true,
		Dynamic:       true,
		HasTimeout:    true,
		Timeout:       5 * time.Minute,
	}
	if err := n.conn.AddSet(n.allowedSet6, nil); err != nil {
		return fmt.Errorf("failed adding IPv6 set: %w", err)
	}

	// Create input chain
	// chain input { type filter hook input priority filter; policy drop; }
	dropPolicy := gnft.ChainPolicyDrop
	chain := &gnft.Chain{
		Name:     chainName,
		Table:    table,
		Type:     gnft.ChainTypeFilter,
		Hooknum:  gnft.ChainHookInput,
		Priority: gnft.ChainPriorityFilter,
		Policy:   &dropPolicy,
	}
	n.conn.AddChain(chain)

	// Accept packets with mark 1
	// meta mark 0x00000001 accept
	//
	// This is needed to avoid conflicting with other tables. nftables has a
	// surprising design where accept verdicts aren't final (unlike drop
	// verdicts), and packets continue to be evaluated by lower priority rules of
	// the same hook type.
	// See:
	// - https://superuser.com/q/1787416
	// - https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#:~:text=If%20a%20packet,chains%20being%20evaluated.
	//
	// For this to work, other higher priority rules on the system *must* mark the packets
	// like so:
	//
	// table inet server {
	//     chain input {
	//         type filter hook input priority -10; policy accept
	//         # Mark SSH traffic to bypass sesame table rules
	//         ct state established,related meta mark 1 accept
	//         tcp dport 22 meta mark set 1 accept
	//     }
	// }
	n.conn.AddRule(&gnft.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{1, 0, 0, 0},
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Accept established/related connections
	// ct state established,related accept
	n.conn.AddRule(&gnft.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{
				Register: 1,
				Key:      expr.CtKeySTATE,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x06, 0x00, 0x00, 0x00}, // ESTABLISHED | RELATED
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Accept packets from allowed IPv4 clients
	// ip saddr . tcp dport @allowed_clients accept
	n.conn.AddRule(&gnft.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// Store layer 3 protocol type to register 1
			&expr.Meta{
				Key:      expr.MetaKeyNFPROTO,
				Register: 1,
			},
			// Match on IPv4
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.NFPROTO_IPV4},
			},
			// Store layer 4 protocol type to register 1
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 1,
			},
			// Match on TCP
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			// Store the source IP address in register 1
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12, // offset in the NFT_PAYLOAD_NETWORK_HEADER
				Len:          4,  // 32 bits
			},
			// Store the TCP destination port in register 9.
			// Why 9? ... ¯\_(ツ)_/¯
			// This was determined by loading the ruleset with `nft -f`, and listing it
			// with `nft --debug=all list ruleset`.
			&expr.Payload{
				DestRegister: 9,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // offset in the NFT_PAYLOAD_TRANSPORT_HEADER
				Len:          2, // 8 bits
			},
			// Lookup using register 1, which will read through the other registers
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        n.allowedSet4.Name,
				SetID:          n.allowedSet4.ID,
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Accept packets from allowed IPv6 clients
	// ip6 saddr . tcp dport @allowed_clients6 accept
	n.conn.AddRule(&gnft.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// Store layer 3 protocol type to register 1
			&expr.Meta{
				Key:      expr.MetaKeyNFPROTO,
				Register: 1,
			},
			// Match on IPv6
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.NFPROTO_IPV6},
			},
			// Store layer 4 protocol type to register 1
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 1,
			},
			// Match on TCP
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			// Store the source IP address in register 1
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       8,  // offset in the NFT_PAYLOAD_NETWORK_HEADER
				Len:          16, // 128 bits
			},
			// Store the TCP destination port in register 2
			&expr.Payload{
				DestRegister: 2,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // offset in the NFT_PAYLOAD_TRANSPORT_HEADER
				Len:          2, // 8 bits
			},
			// Lookup using register 1, which will read through the other registers
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        n.allowedSet6.Name,
				SetID:          n.allowedSet6.ID,
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("failed flushing rules: %w", err)
	}

	n.logger.Debug("setup completed successfully")
	return nil
}

// Allows the given IP address access to the port for a specific duration.
func (n *NFTables) Allow(srcIP netip.Addr, destPort uint16, duration time.Duration) error {
	// Prepare port bytes in network byte order (big endian)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, destPort)

	// Choose the appropriate set based on IP version
	var set *gnft.Set
	var ipBytes []byte

	if srcIP.Is4() {
		set = n.allowedSet4
		ip4 := srcIP.As4()
		ipBytes = ip4[:]
	} else if srcIP.Is6() {
		set = n.allowedSet6
		ip6 := srcIP.As16()
		ipBytes = ip6[:]
	} else {
		return fmt.Errorf("invalid IP address: %s", srcIP)
	}

	// Concatenate IP and port bytes for the set element
	elementData := append(ipBytes, portBytes...)

	// Add the element to the set
	err := n.conn.SetAddElements(set, []gnft.SetElement{
		{
			Key:     elementData,
			Timeout: duration,
		},
	})
	if err != nil {
		return fmt.Errorf("failed adding element to set: %w", err)
	}

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("failed flushing rules: %w", err)
	}

	n.logger.Debug("allowed access to client",
		"ip", srcIP,
		"port", destPort,
		"duration", duration)

	return nil
}
