package wireguard_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ben4523/tailscale-surfshark/internal/wireguard"
)

type fakeRunner struct {
	mu    sync.Mutex
	calls []string
	out   map[string]string
	err   map[string]error
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	f.mu.Lock()
	f.calls = append(f.calls, key)
	err := f.err[key]
	out := f.out[key]
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

func TestUp_CallsWGQuick(t *testing.T) {
	// fakeRunner returns nil for everything, so 'ip link show wg0' looks
	// like wg0 is up — Up will return as soon as it sees wg0.
	r := &fakeRunner{out: map[string]string{}}
	c := wireguard.NewWithRunner(r)
	if err := c.Up(context.Background(), "/etc/wireguard/wg0.conf"); err != nil {
		t.Fatal(err)
	}
	// Both commands must have been issued (in either order — wg-quick runs in
	// a goroutine, the poll runs in the main loop).
	got := map[string]bool{}
	r.mu.Lock()
	for _, c := range r.calls {
		got[c] = true
	}
	r.mu.Unlock()
	if !got["wg-quick up /etc/wireguard/wg0.conf"] {
		t.Errorf("wg-quick up never called; calls = %v", r.calls)
	}
	if !got["ip link show wg0"] {
		t.Errorf("'ip link show wg0' never called; calls = %v", r.calls)
	}
}

func TestUp_FailureBubbles(t *testing.T) {
	// wg-quick fails AND the kernel has no wg0 to show. This mirrors reality:
	// if wg-quick can't create the interface, 'ip link show wg0' fails too.
	r := &fakeRunner{err: map[string]error{
		"wg-quick up /etc/wireguard/wg0.conf": errors.New("nope"),
		"ip link show wg0":                    errors.New("Device \"wg0\" does not exist."),
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
