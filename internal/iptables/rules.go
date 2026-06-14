package iptables

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

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

// ApplyBase installs NAT + FORWARD rules. Idempotent: existing rules are deleted then re-added.
func (m *Manager) ApplyBase(ctx context.Context, tsIface, wgIface, lanIface string) error {
	rules := []ruleSpec{
		{table: "nat", chain: "POSTROUTING", args: []string{"-o", wgIface, "-j", "MASQUERADE"}},
		{chain: "FORWARD", args: []string{"-i", tsIface, "-o", wgIface, "-j", "ACCEPT"}},
		{chain: "FORWARD", args: []string{"-i", wgIface, "-o", tsIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
	}
	for _, r := range rules {
		if err := m.ensureRule(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) ArmKillSwitch(ctx context.Context, tsIface, lanIface string) error {
	return m.ensureRule(ctx, ruleSpec{
		chain: "FORWARD",
		args:  []string{"-i", tsIface, "-o", lanIface, "-j", "DROP"},
	})
}

func (m *Manager) DisarmKillSwitch(ctx context.Context, tsIface, lanIface string) error {
	return m.deleteRule(ctx, ruleSpec{
		chain: "FORWARD",
		args:  []string{"-i", tsIface, "-o", lanIface, "-j", "DROP"},
	})
}

type ruleSpec struct {
	table string
	chain string
	args  []string
}

func (m *Manager) ensureRule(ctx context.Context, r ruleSpec) error {
	_ = m.deleteRule(ctx, r) // ignore errors on delete (may not exist yet)
	cmd := []string{}
	if r.table != "" {
		cmd = append(cmd, "-t", r.table)
	}
	cmd = append(cmd, "-A", r.chain)
	cmd = append(cmd, r.args...)
	_, err := m.r.Run(ctx, "iptables", cmd...)
	return err
}

func (m *Manager) deleteRule(ctx context.Context, r ruleSpec) error {
	cmd := []string{}
	if r.table != "" {
		cmd = append(cmd, "-t", r.table)
	}
	cmd = append(cmd, "-D", r.chain)
	cmd = append(cmd, r.args...)
	_, err := m.r.Run(ctx, "iptables", cmd...)
	return err
}
