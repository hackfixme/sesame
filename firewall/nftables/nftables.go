package nftables

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	ftypes "go.hackfix.me/sesame/firewall/types"
)

const (
	tableName       = "sesame"
	chainName       = "input"
	setAllowed4Name = "allowed_clients"
	setAllowed6Name = "allowed_clients6"
)

// NFTables is an abstraction over the Linux nftables firewall.
type NFTables struct {
	conn  *gnft.Conn
	table *gnft.Table
	// IPv4/6 sets for allowed source address and destination port pairs.
	allowed               map[int]*gnft.Set
	defaultAccessDuration time.Duration
	logger                *slog.Logger
}

var _ ftypes.Firewall = (*NFTables)(nil)

// New returns a new NFTables instance. It returns an error if the netlink
// connection to the kernel fails.
func New(defaultAccessDuration time.Duration, logger *slog.Logger) (*NFTables, error) {
	conn, err := gnft.New()
	if err != nil {
		return nil, fmt.Errorf("failed establishing netlink connection: %w", err)
	}

	nft := &NFTables{
		conn:                  conn,
		allowed:               make(map[int]*gnft.Set),
		defaultAccessDuration: defaultAccessDuration,
		logger:                logger.With("type", "nftables"),
	}

	// Try getting the existing table and named sets if they exist. Otherwise
	// assume they will be created by Init.
	nft.table, err = conn.ListTableOfFamily(tableName, gnft.TableFamilyINet)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed getting table %s: %w", tableName, err)
	}

	if nft.table != nil {
		nft.allowed[32], err = conn.GetSetByName(nft.table, setAllowed4Name)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed getting set '%s': %w", setAllowed4Name, err)
		}

		nft.allowed[128], err = conn.GetSetByName(nft.table, setAllowed6Name)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed getting set '%s': %w", setAllowed6Name, err)
		}
	}

	return nft, nil
}

// Init initializes the firewall by creating the nftables ruleset. It is
// idempotent, and won't recreate objects if they already exist.
//
// It creates the following ruleset:
//
//	table inet sesame {
//	    set allowed_clients {
//	        type ipv4_addr . inet_service
//	        flags interval,timeout
//	        timeout 5m
//	    }
//
//	    set allowed_clients6 {
//	        type ipv6_addr . inet_service
//	        flags interval,timeout
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
//
//nolint:funlen // This is easier to understand as a single long function.
func (n *NFTables) Init() (err error) {
	var init bool
	defer func() {
		if err == nil {
			if ferr := n.conn.Flush(); ferr != nil {
				err = fmt.Errorf("failed flushing rules: %w", ferr)
			} else if init {
				n.logger.Info("firewall initialized")
			}
		}
	}()

	// table inet sesame {}
	if n.table, err = n.conn.ListTableOfFamily(tableName, gnft.TableFamilyINet); errors.Is(err, os.ErrNotExist) {
		n.table = &gnft.Table{
			Name:   tableName,
			Family: gnft.TableFamilyINet,
		}
		n.conn.CreateTable(n.table)
		n.logger.Debug("initializing firewall")
		init = true
	} else if err != nil {
		return fmt.Errorf("failed getting table %s: %w", tableName, err)
	}

	// IPv4 and IPv6 sets, whose elements are concatenations of the source IP
	// address and the destination port.
	// set allowed_clients {
	//     type ipv4_addr . inet_service
	//     flags interval,timeout
	//     timeout 5m
	// }
	if n.allowed[32], err = n.conn.GetSetByName(n.table, setAllowed4Name); errors.Is(err, os.ErrNotExist) {
		n.allowed[32] = &gnft.Set{
			ID:            1,
			Name:          setAllowed4Name,
			Table:         n.table,
			KeyType:       gnft.MustConcatSetType(gnft.TypeIPAddr, gnft.TypeInetService),
			Concatenation: true,
			Interval:      true,
			HasTimeout:    true,
			Timeout:       n.defaultAccessDuration,
		}
		if err = n.conn.AddSet(n.allowed[32], nil); err != nil {
			return fmt.Errorf("failed adding set '%s': %w", setAllowed4Name, err)
		}
	} else if err != nil {
		return fmt.Errorf("failed getting set '%s': %w", setAllowed4Name, err)
	}

	// set allowed_clients6 {
	//     type ipv6_addr . inet_service
	//     flags interval,timeout
	//     timeout 5m
	// }
	if n.allowed[128], err = n.conn.GetSetByName(n.table, setAllowed6Name); errors.Is(err, os.ErrNotExist) {
		n.allowed[128] = &gnft.Set{
			ID:            2,
			Name:          setAllowed6Name,
			Table:         n.table,
			KeyType:       gnft.MustConcatSetType(gnft.TypeIP6Addr, gnft.TypeInetService),
			Concatenation: true,
			Interval:      true,
			HasTimeout:    true,
			Timeout:       n.defaultAccessDuration,
		}
		if err = n.conn.AddSet(n.allowed[128], nil); err != nil {
			return fmt.Errorf("failed adding set '%s': %w", setAllowed6Name, err)
		}
	} else if err != nil {
		return fmt.Errorf("failed getting set '%s': %w", setAllowed6Name, err)
	}

	// chain input { type filter hook input priority filter; policy drop; }
	var chain *gnft.Chain
	_, err = n.conn.ListChain(n.table, chainName)
	switch {
	// NOTE: Unfortunately, ListChain returns a non-wrapped error, so we can't use
	// errors.Is(err, os.ErrNotExist) here.
	// https://github.com/google/nftables/blob/68e1406c13281ebc65b8cb5733ee5882244809d5/chain.go#L218
	case err != nil && strings.Contains(err.Error(), "no such file or directory"):
		dropPolicy := gnft.ChainPolicyDrop
		chain = &gnft.Chain{
			Name:     chainName,
			Table:    n.table,
			Type:     gnft.ChainTypeFilter,
			Hooknum:  gnft.ChainHookInput,
			Priority: gnft.ChainPriorityFilter,
			Policy:   &dropPolicy,
		}
		n.conn.AddChain(chain)
	case err != nil:
		return fmt.Errorf("failed getting chain '%s': %w", chainName, err)
	default:
		// The chain exists, so assume that all rules were previously created as well,
		// in order to avoid adding duplicate rules. We could in theory check the rules
		// themselves, but there's no straightforward way to check rule equality, so it
		// would require comparing their count, handle, position, etc.
		return nil
	}

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
		Table: n.table,
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
		Table: n.table,
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
	//nolint:dupl // This rule is very similar to the IPv6 one, but not the same.
	n.conn.AddRule(&gnft.Rule{
		Table: n.table,
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
			// with `nft --debug=netlink list ruleset`.
			&expr.Payload{
				DestRegister: 9,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // offset in the NFT_PAYLOAD_TRANSPORT_HEADER
				Len:          2, // 8 bits
			},
			// Lookup using register 1, which will read through the other registers
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        n.allowed[32].Name,
				SetID:          n.allowed[32].ID,
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Accept packets from allowed IPv6 clients
	// ip6 saddr . tcp dport @allowed_clients6 accept
	//nolint:dupl // This rule is very similar to the IPv4 one, but not the same.
	n.conn.AddRule(&gnft.Rule{
		Table: n.table,
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
				SetName:        n.allowed[128].Name,
				SetID:          n.allowed[128].ID,
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	return nil
}

// Allow gives the specified IP address range access to the port for a specific duration.
func (n *NFTables) Allow(ipRange netipx.IPRange, destPort uint16, duration time.Duration) error {
	if !ipRange.IsValid() {
		return fmt.Errorf("invalid IP address range: %s", ipRange)
	}
	if destPort == 0 {
		return fmt.Errorf("invalid port: %d", destPort)
	}

	var (
		ipRangeStart = ipRange.From().AsSlice()
		ipRangeEnd   = ipRange.To().AsSlice()
	)

	// Port in binary network byte order (big endian)
	portBytes := make([]byte, 4)
	binary.BigEndian.PutUint16(portBytes, destPort)

	keyStart := slices.Concat(ipRangeStart, portBytes)
	keyEnd := slices.Concat(ipRangeEnd, portBytes)

	set := n.allowed[ipRange.From().BitLen()]
	err := n.conn.SetAddElements(set, []gnft.SetElement{
		{
			Key:     keyStart,
			KeyEnd:  keyEnd,
			Timeout: duration,
		},
	})
	if err != nil {
		return fmt.Errorf("failed adding element to set: %w", err)
	}

	if err = n.conn.Flush(); err != nil {
		return fmt.Errorf("failed flushing rules: %w", err)
	}

	n.logger.Debug("allowed access",
		"range", ipRange.String(),
		"port", destPort,
		"duration", duration)

	return nil
}
