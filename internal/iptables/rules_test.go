package iptables_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/iptables"
)

type recRunner struct {
	calls []string
	errOn map[string]error
}

func (r *recRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, cmd)
	for k, e := range r.errOn {
		if strings.Contains(cmd, k) {
			return nil, e
		}
	}
	return nil, nil
}

func TestApplyBase_BuildsExpectedNftTable(t *testing.T) {
	r := &recRunner{}
	m := iptables.NewWithRunner(r)
	if err := m.ApplyBase(context.Background(), "tailscale0", "wg0", "eth0"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, "\n")
	wants := []string{
		"nft delete table ip surfshark_exit",
		"nft add table ip surfshark_exit",
		"nft add chain ip surfshark_exit forward { type filter hook forward priority 0",
		"nft add chain ip surfshark_exit postrouting { type nat hook postrouting priority 100",
		"nft add rule ip surfshark_exit postrouting oifname wg0 masquerade",
		"nft add rule ip surfshark_exit forward iifname tailscale0 oifname wg0 accept",
		"nft add rule ip surfshark_exit forward iifname wg0 oifname tailscale0 ct state related,established accept",
	}
	for _, w := range wants {
		if !strings.Contains(joined, w) {
			t.Errorf("missing %q in:\n%s", w, joined)
		}
	}
}

func TestArmKillSwitch_AddsDropChain(t *testing.T) {
	r := &recRunner{}
	m := iptables.NewWithRunner(r)
	if err := m.ArmKillSwitch(context.Background(), "tailscale0", "eth0"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, "\n")
	for _, w := range []string{
		"nft add chain ip surfshark_exit killswitch",
		"nft add rule ip surfshark_exit killswitch iifname tailscale0 oifname eth0 drop",
	} {
		if !strings.Contains(joined, w) {
			t.Errorf("missing %q in:\n%s", w, joined)
		}
	}
}

func TestDisarmKillSwitch_DeletesChain(t *testing.T) {
	r := &recRunner{}
	m := iptables.NewWithRunner(r)
	if err := m.DisarmKillSwitch(context.Background(), "tailscale0", "eth0"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "nft delete chain ip surfshark_exit killswitch") {
		t.Errorf("missing delete chain in:\n%s", joined)
	}
}

func TestDisarmKillSwitch_NoOpWhenAbsent(t *testing.T) {
	r := &recRunner{errOn: map[string]error{
		"delete chain": errors.New("No such file or directory"),
	}}
	m := iptables.NewWithRunner(r)
	if err := m.DisarmKillSwitch(context.Background(), "tailscale0", "eth0"); err != nil {
		t.Errorf("should swallow 'No such' error, got: %v", err)
	}
}

type fnRunner struct {
	f func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (r *fnRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r.f(ctx, name, args...)
}

func TestApplyBase_TableDeleteFailureIsTolerated(t *testing.T) {
	calls := 0
	adapter := &fnRunner{f: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("Error: No such file or directory")
		}
		return nil, nil
	}}
	m := iptables.NewWithRunner(adapter)
	if err := m.ApplyBase(context.Background(), "tailscale0", "wg0", "eth0"); err != nil {
		t.Fatalf("delete-table failure should be tolerated, got: %v", err)
	}
}
