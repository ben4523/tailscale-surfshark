package tailscale_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/tailscale"
)

type fakeRunner struct {
	resp map[string]string
	err  map[string]error
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	if e := f.err[key]; e != nil {
		return nil, e
	}
	return []byte(f.resp[key]), nil
}

func TestIPv4(t *testing.T) {
	r := &fakeRunner{resp: map[string]string{
		"tailscale ip -4": "100.64.0.5\n",
	}}
	c := tailscale.NewWithRunner(r)
	ip, err := c.IPv4(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ip != "100.64.0.5" {
		t.Errorf("ip = %q", ip)
	}
}

func TestWhois_FoundUser(t *testing.T) {
	r := &fakeRunner{resp: map[string]string{
		"tailscale whois --json 100.64.0.10": `{"UserProfile":{"LoginName":"ben@example.com"}}`,
	}}
	c := tailscale.NewWithRunner(r)
	user, err := c.Whois(context.Background(), "100.64.0.10")
	if err != nil {
		t.Fatal(err)
	}
	if user != "ben@example.com" {
		t.Errorf("user = %q", user)
	}
}

func TestWhois_Error(t *testing.T) {
	r := &fakeRunner{err: map[string]error{
		"tailscale whois --json 1.2.3.4": errors.New("not in tailnet"),
	}}
	c := tailscale.NewWithRunner(r)
	_, err := c.Whois(context.Background(), "1.2.3.4")
	if err == nil {
		t.Fatal("expected error")
	}
}
