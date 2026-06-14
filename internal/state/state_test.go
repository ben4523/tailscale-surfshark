package state_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbitton/tailscale-surfshark/internal/state"
)

func TestDefault(t *testing.T) {
	s := state.Default()
	if s.Version != 1 {
		t.Errorf("version = %d", s.Version)
	}
	if s.Surfshark.Toggle {
		t.Error("toggle should default false")
	}
}

func TestLoadNotExist_ReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	s, err := state.Load(filepath.Join(dir, "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 1 {
		t.Errorf("expected default state")
	}
}

func TestSaveLoad_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := state.Default()
	s.Surfshark.Toggle = true
	s.Surfshark.CurrentLocation = "us-nyc"
	s.Surfshark.PreferredLocations = []string{"us-nyc", "fr-par"}
	s.Stats.PublicIP = "1.2.3.4"
	now := time.Now().UTC().Truncate(time.Second)
	s.Stats.LastMeasured = now

	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Surfshark.CurrentLocation != "us-nyc" {
		t.Errorf("location = %q", loaded.Surfshark.CurrentLocation)
	}
	if !loaded.Stats.LastMeasured.Equal(now) {
		t.Errorf("timestamp not preserved: %v vs %v", loaded.Stats.LastMeasured, now)
	}
}

func TestSave_Atomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := state.Default()
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf(".tmp leftover: err=%v", err)
	}
}

func TestLoad_CorruptedFile_BacksUpAndReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 1 {
		t.Errorf("expected default after corruption")
	}
	matches, _ := filepath.Glob(path + ".broken-*")
	if len(matches) == 0 {
		t.Errorf("expected backup file, none found")
	}
}
