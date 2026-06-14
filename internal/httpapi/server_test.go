package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ben4523/tailscale-surfshark/internal/eventbus"
	"github.com/ben4523/tailscale-surfshark/internal/httpapi"
	"github.com/ben4523/tailscale-surfshark/internal/state"
)

type allowAllWhois struct{}

func (allowAllWhois) Whois(ctx context.Context, ip string) (string, error) {
	return "ben@example.com", nil
}

type fakeOps struct {
	toggleCalls   []bool
	switchCalls   []string
	refreshCalled atomic.Bool
	available     []string
}

func (f *fakeOps) Toggle(ctx context.Context, on bool) error {
	f.toggleCalls = append(f.toggleCalls, on)
	return nil
}
func (f *fakeOps) SwitchLocation(ctx context.Context, loc string) error {
	f.switchCalls = append(f.switchCalls, loc)
	return nil
}
func (f *fakeOps) Refresh(ctx context.Context) error {
	f.refreshCalled.Store(true)
	return nil
}
func (f *fakeOps) AvailableLocations() []string { return f.available }
func (f *fakeOps) SetPreferred(ctx context.Context, locs []string) error {
	return nil
}

func newTestServer(t *testing.T) (*httptest.Server, *fakeOps, *state.State) {
	st := state.Default()
	bus := eventbus.New(4)
	ops := &fakeOps{available: []string{"us-nyc", "fr-par"}}
	// httptest.NewServer routes requests over loopback, so the auth
	// middleware treats every test request as "proxied via tailscale serve"
	// and short-circuits whois. Use the "*" allow-list so the tests focus
	// on handler behavior, not on identity wiring (the auth path itself is
	// covered by the auth package's unit tests).
	srv := httpapi.NewServer(httpapi.Deps{
		Whois:   allowAllWhois{},
		Allowed: []string{"*"},
		State:   st,
		Bus:     bus,
		Ops:     ops,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, ops, st
}

func TestHealthz_NoAuthRequired(t *testing.T) {
	ts, _, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status %d", resp.StatusCode)
	}
}

func TestStatus_ReturnsJSON(t *testing.T) {
	ts, _, _ := newTestServer(t)
	resp, _ := http.Get(ts.URL + "/api/status")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var data map[string]any
	json.NewDecoder(resp.Body).Decode(&data)
	if _, ok := data["surfshark"]; !ok {
		t.Errorf("missing surfshark field")
	}
}

func TestToggle_ForwardsToOps(t *testing.T) {
	ts, ops, _ := newTestServer(t)
	resp, _ := http.Post(ts.URL+"/api/surfshark/toggle", "application/json",
		strings.NewReader(`{"enabled": true}`))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(ops.toggleCalls) != 1 || !ops.toggleCalls[0] {
		t.Errorf("toggle calls = %v", ops.toggleCalls)
	}
}

func TestSwitchLocation_ForwardsToOps(t *testing.T) {
	ts, ops, _ := newTestServer(t)
	resp, _ := http.Post(ts.URL+"/api/surfshark/location", "application/json",
		strings.NewReader(`{"name":"us-nyc"}`))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(ops.switchCalls) != 1 || ops.switchCalls[0] != "us-nyc" {
		t.Errorf("switch calls = %v", ops.switchCalls)
	}
}

func TestRefresh_Returns202(t *testing.T) {
	ts, ops, _ := newTestServer(t)
	resp, _ := http.Post(ts.URL+"/api/surfshark/refresh", "application/json", nil)
	if resp.StatusCode != 202 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for i := 0; i < 50; i++ {
		if ops.refreshCalled.Load() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("refresh was never called")
}
