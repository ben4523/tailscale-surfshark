package surfshark_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/surfshark"
)

func TestLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/login" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["username"] != "u" || body["password"] != "p" {
			t.Errorf("bad body: %v", body)
		}
		json.NewEncoder(w).Encode(map[string]string{"token": "tok", "renewToken": "rt"})
	}))
	defer srv.Close()

	c := surfshark.NewClient(srv.URL)
	tok, err := c.Login(context.Background(), "u", "p")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok" {
		t.Errorf("token = %q", tok)
	}
}

func TestLogin_BadCreds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"invalid creds"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := surfshark.NewClient(srv.URL)
	_, err := c.Login(context.Background(), "u", "p")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v", err)
	}
}

func TestRegisterPubKey_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c := surfshark.NewClient(srv.URL)
	if err := c.RegisterPubKey(context.Background(), "tok", "PUBKEY=="); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterPubKey_AlreadyExists_IsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"public key already exists"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	c := surfshark.NewClient(srv.URL)
	if err := c.RegisterPubKey(context.Background(), "tok", "PUBKEY=="); err != nil {
		t.Fatalf("should be idempotent: %v", err)
	}
}

func TestListServers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"id": "us-nyc", "country": "United States", "country_code": "us", "location": "New York", "connection_name": "us-nyc.prod.surfshark.com", "pub_key": "PUB1", "host": "1.2.3.4"},
			{"id": "fr-par", "country": "France", "country_code": "fr", "location": "Paris", "connection_name": "fr-par.prod.surfshark.com", "pub_key": "PUB2", "host": "5.6.7.8"},
		})
	}))
	defer srv.Close()
	c := surfshark.NewClient(srv.URL)
	servers, err := c.ListServers(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("got %d servers", len(servers))
	}
	if servers[0].ID != "us-nyc" {
		t.Errorf("first id = %q", servers[0].ID)
	}
}
