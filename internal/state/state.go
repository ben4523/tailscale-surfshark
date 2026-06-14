package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type State struct {
	Version    int             `json:"version"`
	Surfshark  SurfsharkState  `json:"surfshark"`
	KillSwitch KillSwitchState `json:"kill_switch"`
	Stats      StatsCache      `json:"stats_cache"`

	mu sync.Mutex `json:"-"`
}

type SurfsharkState struct {
	Toggle             bool       `json:"toggle"`
	CurrentLocation    string     `json:"current_location"`
	CurrentEndpointIP  string     `json:"current_endpoint_ip"` // resolved IPv4 of the active peer; needed to clean up the /32 route exception
	PreferredLocations []string   `json:"preferred_locations"`
	LastRefresh        *time.Time `json:"last_refresh"`
	LastFailover       *time.Time `json:"last_failover"`
}

type KillSwitchState struct {
	EnabledByEnv   bool `json:"enabled_by_env"`
	CurrentlyArmed bool `json:"currently_armed"`
}

type StatsCache struct {
	PublicIP         string    `json:"public_ip"`
	PublicIPLocation string    `json:"public_ip_location"`
	LastMeasured     time.Time `json:"last_measured"`
	WG0LatencyMS     int       `json:"wg0_latency_ms"`
	WG0LastHandshake time.Time `json:"wg0_last_handshake"`
}

func Default() *State {
	return &State{Version: 1}
}

func Load(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		backup := fmt.Sprintf("%s.broken-%s", path, time.Now().UTC().Format("20060102T150405"))
		_ = os.Rename(path, backup)
		return Default(), nil
	}
	if s.Version == 0 {
		s.Version = 1
	}
	return &s, nil
}

func (s *State) Save(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
