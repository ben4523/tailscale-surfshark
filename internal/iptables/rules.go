// Package iptables manages the container's NAT + FORWARD + kill-switch rules.
//
// Despite the package name, it uses the modern `nft` (nftables) CLI rather
// than the legacy `iptables` binary, because Synology DSM kernels miss the
// xt_MASQUERADE extension needed by iptables-nft. nftables itself works on
// the older nf_tables netlink API that DSM ships.
//
// Everything lives in a dedicated nftables table named "surfshark_exit", so
// we can flush it without touching Tailscale's own ts-* chains.
package iptables

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

const tableName = "surfshark_exit"

type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, string(out))
	}
	return out, nil
}

type Manager struct{ r Runner }

func New() *Manager                   { return &Manager{r: execRunner{}} }
func NewWithRunner(r Runner) *Manager { return &Manager{r: r} }

// ApplyBase creates (idempotently) the surfshark_exit nft table with:
//   - a NAT postrouting chain that masquerades anything leaving wgIface
//   - a filter forward chain that accepts tailscale<->wg traffic in both directions
//
// Idempotency: the table is deleted first (silently if absent), then recreated.
func (m *Manager) ApplyBase(ctx context.Context, tsIface, wgIface, lanIface string) error {
	// Best-effort drop; ignore "no such table" errors.
	_, _ = m.r.Run(ctx, "nft", "delete", "table", "ip", tableName)

	steps := [][]string{
		{"add", "table", "ip", tableName},
		{"add", "chain", "ip", tableName, "forward",
			"{ type filter hook forward priority 0 ; policy accept ; }"},
		{"add", "chain", "ip", tableName, "postrouting",
			"{ type nat hook postrouting priority 100 ; }"},
		{"add", "rule", "ip", tableName, "postrouting",
			"oifname", wgIface, "masquerade"},
		{"add", "rule", "ip", tableName, "forward",
			"iifname", tsIface, "oifname", wgIface, "accept"},
		{"add", "rule", "ip", tableName, "forward",
			"iifname", wgIface, "oifname", tsIface,
			"ct", "state", "related,established", "accept"},
	}
	for _, s := range steps {
		if _, err := m.r.Run(ctx, "nft", s...); err != nil {
			return err
		}
	}
	return nil
}

// ArmKillSwitch installs a separate "killswitch" chain inside surfshark_exit
// that DROPs forward traffic from tsIface to lanIface. Kept as its own chain
// so it can be toggled without touching the base forwarding rules. Idempotent.
func (m *Manager) ArmKillSwitch(ctx context.Context, tsIface, lanIface string) error {
	// Best-effort delete of any prior killswitch chain.
	_, _ = m.r.Run(ctx, "nft", "delete", "chain", "ip", tableName, "killswitch")

	steps := [][]string{
		{"add", "chain", "ip", tableName, "killswitch",
			"{ type filter hook forward priority -10 ; }"},
		{"add", "rule", "ip", tableName, "killswitch",
			"iifname", tsIface, "oifname", lanIface, "drop"},
	}
	for _, s := range steps {
		if _, err := m.r.Run(ctx, "nft", s...); err != nil {
			return err
		}
	}
	return nil
}

// DisarmKillSwitch removes the killswitch chain. No-op if not present.
func (m *Manager) DisarmKillSwitch(ctx context.Context, tsIface, lanIface string) error {
	_, err := m.r.Run(ctx, "nft", "delete", "chain", "ip", tableName, "killswitch")
	if err != nil && strings.Contains(err.Error(), "No such") {
		return nil
	}
	return err
}
