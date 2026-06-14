package surfshark_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/surfshark"
)

func TestListServers_NoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v4/server/clusters/generic" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("must not send Authorization for public endpoint")
		}
		if r.Header.Get("User-Agent") == "" {
			t.Errorf("must send User-Agent (Cloudflare blocks bare clients)")
		}
		json.NewEncoder(w).Encode([]map[string]any{
			{
				"id":             "uuid-1",
				"country":        "United States",
				"countryCode":    "us",
				"region":         "Americas",
				"location":       "New York",
				"connectionName": "us-nyc.prod.surfshark.com",
				"pubKey":         "PUB1",
				"load":           42,
			},
			{
				"id":             "uuid-2",
				"country":        "France",
				"countryCode":    "fr",
				"region":         "Europe",
				"location":       "Paris",
				"connectionName": "fr-par.prod.surfshark.com",
				"pubKey":         "PUB2",
				"load":           18,
			},
		})
	}))
	defer srv.Close()

	c := surfshark.NewClient(srv.URL)
	servers, err := c.ListServers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("got %d servers", len(servers))
	}
	if got, want := servers[0].Slug(), "us-nyc"; got != want {
		t.Errorf("slug = %q, want %q", got, want)
	}
	if got, want := servers[0].Display(), "us-nyc — New York, US"; got != want {
		t.Errorf("display = %q, want %q", got, want)
	}
}

func TestListServers_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := surfshark.NewClient(srv.URL)
	_, err := c.ListServers(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSlug_FallsBackToConnectionNameWhenNoDots(t *testing.T) {
	s := surfshark.Server{ConnectionName: "noformat"}
	if got := s.Slug(); got != "noformat" {
		t.Errorf("got %q", got)
	}
}
