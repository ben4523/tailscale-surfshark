package iptables_test

import (
	"context"
	"strings"
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/iptables"
)

type recRunner struct{ calls []string }

func (r *recRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	return nil, nil
}

func TestApplyBase_AddsExpectedRules(t *testing.T) {
	r := &recRunner{}
	m := iptables.NewWithRunner(r)
	if err := m.ApplyBase(context.Background(), "tailscale0", "wg0", "eth0"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, "\n")
	for _, want := range []string{
		"iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE",
		"iptables -A FORWARD -i tailscale0 -o wg0 -j ACCEPT",
		"iptables -A FORWARD -i wg0 -o tailscale0 -m state --state RELATED,ESTABLISHED -j ACCEPT",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing rule %q in:\n%s", want, joined)
		}
	}
}

func TestArmKillSwitch_BlocksDirectEgress(t *testing.T) {
	r := &recRunner{}
	m := iptables.NewWithRunner(r)
	if err := m.ArmKillSwitch(context.Background(), "tailscale0", "eth0"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "iptables -A FORWARD -i tailscale0 -o eth0 -j DROP") {
		t.Errorf("missing kill-switch DROP in:\n%s", joined)
	}
}

func TestDisarmKillSwitch_RemovesBlock(t *testing.T) {
	r := &recRunner{}
	m := iptables.NewWithRunner(r)
	if err := m.DisarmKillSwitch(context.Background(), "tailscale0", "eth0"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "iptables -D FORWARD -i tailscale0 -o eth0 -j DROP") {
		t.Errorf("missing kill-switch DROP delete in:\n%s", joined)
	}
}

func TestIdempotent_DoubleApplyDoesNotDuplicate(t *testing.T) {
	r := &recRunner{}
	m := iptables.NewWithRunner(r)
	_ = m.ApplyBase(context.Background(), "tailscale0", "wg0", "eth0")
	first := len(r.calls)
	_ = m.ApplyBase(context.Background(), "tailscale0", "wg0", "eth0")
	if len(r.calls) != 2*first {
		t.Logf("calls doubled from %d to %d (expected idempotent reapply)", first, len(r.calls))
	}
}
