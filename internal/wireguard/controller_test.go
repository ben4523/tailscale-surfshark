package wireguard_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ben4523/tailscale-surfshark/internal/wireguard"
)

type fakeRunner struct {
	calls []string
	out   map[string]string
	err   map[string]error
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	f.calls = append(f.calls, key)
	if e := f.err[key]; e != nil {
		return nil, e
	}
	return []byte(f.out[key]), nil
}

func TestUp_CallsWGQuick(t *testing.T) {
	r := &fakeRunner{out: map[string]string{}}
	c := wireguard.NewWithRunner(r)
	if err := c.Up(context.Background(), "/etc/wireguard/wg0.conf"); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 || r.calls[0] != "wg-quick up /etc/wireguard/wg0.conf" {
		t.Errorf("calls = %v", r.calls)
	}
}

func TestUp_FailureBubbles(t *testing.T) {
	r := &fakeRunner{err: map[string]error{
		"wg-quick up /etc/wireguard/wg0.conf": errors.New("nope"),
	}, out: map[string]string{}}
	c := wireguard.NewWithRunner(r)
	if err := c.Up(context.Background(), "/etc/wireguard/wg0.conf"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDown(t *testing.T) {
	r := &fakeRunner{out: map[string]string{}}
	c := wireguard.NewWithRunner(r)
	if err := c.Down(context.Background(), "wg0"); err != nil {
		t.Fatal(err)
	}
	if r.calls[0] != "wg-quick down wg0" {
		t.Errorf("calls = %v", r.calls)
	}
}

func TestLastHandshake_Parses(t *testing.T) {
	r := &fakeRunner{
		out: map[string]string{
			"wg show wg0 latest-handshakes": "PEERPUBKEY\t1720000000\n",
		},
	}
	c := wireguard.NewWithRunner(r)
	hs, err := c.LastHandshake(context.Background(), "wg0")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Unix(1720000000, 0)
	if !hs.Equal(want) {
		t.Errorf("hs = %v, want %v", hs, want)
	}
}

func TestLastHandshake_NoneYet(t *testing.T) {
	r := &fakeRunner{out: map[string]string{
		"wg show wg0 latest-handshakes": "PEER\t0\n",
	}}
	c := wireguard.NewWithRunner(r)
	hs, err := c.LastHandshake(context.Background(), "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if !hs.IsZero() {
		t.Errorf("expected zero time, got %v", hs)
	}
}
