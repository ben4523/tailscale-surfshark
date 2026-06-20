package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	payload := map[string]any{
		"version":             s.d.State.Version,
		"surfshark":           s.d.State.Surfshark,
		"kill_switch":         s.d.State.KillSwitch,
		"stats":               s.d.State.Stats,
		"available_locations": s.d.Ops.AvailableLocations(),
	}
	writeJSON(w, 200, payload)
}

func (s *Server) handleToggle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := s.d.Ops.Toggle(r.Context(), body.Enabled); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleSwitch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if body.Name == "" {
		http.Error(w, "name required", 400)
		return
	}
	if err := s.d.Ops.SwitchLocation(r.Context(), body.Name); err != nil {
		http.Error(w, err.Error(), 504)
		return
	}
	writeJSON(w, 200, map[string]string{"location": body.Name})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	// Detach: don't tie background work to the request context
	go func() {
		_ = s.d.Ops.Refresh(context.Background())
	}()
	writeJSON(w, 202, map[string]string{"status": "started"})
}

func (s *Server) handleKillSwitch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := s.d.Ops.SetKillSwitch(r.Context(), body.Enabled); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string]bool{"user_on": body.Enabled})
}

func (s *Server) handlePreferred(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Locations []string `json:"locations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := s.d.Ops.SetPreferred(r.Context(), body.Locations); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string][]string{"locations": body.Locations})
}

