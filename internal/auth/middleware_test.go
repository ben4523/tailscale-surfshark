package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ben4523/tailscale-surfshark/internal/auth"
)

type fakeWhois func(ctx context.Context, ip string) (string, error)

func (f fakeWhois) Whois(ctx context.Context, ip string) (string, error) { return f(ctx, ip) }

func TestMiddleware_AllowsWhitelistedUser(t *testing.T) {
	mw := auth.New(fakeWhois(func(ctx context.Context, ip string) (string, error) {
		return "ben@example.com", nil
	}), []string{"ben@example.com"})

	called := false
	h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if got := auth.UserFromContext(r.Context()); got != "ben@example.com" {
			t.Errorf("user in ctx = %q", got)
		}
		w.WriteHeader(204)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "100.64.0.5:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatal("handler not called")
	}
	if rec.Code != 204 {
		t.Errorf("status %d", rec.Code)
	}
}

func TestMiddleware_RejectsNonWhitelisted(t *testing.T) {
	mw := auth.New(fakeWhois(func(ctx context.Context, ip string) (string, error) {
		return "eve@example.com", nil
	}), []string{"ben@example.com"})

	h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not reach handler")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "100.64.0.7:5678"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestMiddleware_RejectsWhoisError(t *testing.T) {
	mw := auth.New(fakeWhois(func(ctx context.Context, ip string) (string, error) {
		return "", errors.New("not in tailnet")
	}), []string{"ben@example.com"})

	h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not reach")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}
