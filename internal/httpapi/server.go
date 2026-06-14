package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ben4523/tailscale-surfshark/internal/auth"
	"github.com/ben4523/tailscale-surfshark/internal/eventbus"
	"github.com/ben4523/tailscale-surfshark/internal/state"
)

type Ops interface {
	Toggle(ctx context.Context, on bool) error
	SwitchLocation(ctx context.Context, loc string) error
	Refresh(ctx context.Context) error
	SetPreferred(ctx context.Context, locs []string) error
	AvailableLocations() []string
}

type Deps struct {
	Whois   auth.WhoisFunc
	Allowed []string
	State   *state.State
	Bus     *eventbus.Bus
	Ops     Ops
	Logger  auth.Logger // optional; used to log auth failures
}

type Server struct {
	d   Deps
	mw  *auth.Middleware
	mux *http.ServeMux
}

func NewServer(d Deps) *Server {
	mw := auth.New(d.Whois, d.Allowed)
	if d.Logger != nil {
		mw.SetLogger(d.Logger)
	}
	s := &Server{
		d:   d,
		mw:  mw,
		mux: http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	// Unauthenticated:
	s.mux.HandleFunc("/api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	// Authenticated:
	s.mux.Handle("/api/status", s.mw.Wrap(http.HandlerFunc(s.handleStatus)))
	s.mux.Handle("/api/surfshark/toggle", s.mw.Wrap(http.HandlerFunc(s.handleToggle)))
	s.mux.Handle("/api/surfshark/location", s.mw.Wrap(http.HandlerFunc(s.handleSwitch)))
	s.mux.Handle("/api/surfshark/refresh", s.mw.Wrap(http.HandlerFunc(s.handleRefresh)))
	s.mux.Handle("/api/surfshark/preferred", s.mw.Wrap(http.HandlerFunc(s.handlePreferred)))
	s.mux.Handle("/api/events", s.mw.Wrap(http.HandlerFunc(s.handleEvents)))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
