package surfshark_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/surfshark"
)

func TestConfigStore_KeypairPersistence(t *testing.T) {
	dir := t.TempDir()
	s := surfshark.NewConfigStore(dir)
	priv1, pub1, err := s.EnsureKeypair()
	if err != nil {
		t.Fatal(err)
	}
	priv2, pub2, err := s.EnsureKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if priv1 != priv2 || pub1 != pub2 {
		t.Errorf("keypair changed on second call")
	}
}

func TestConfigStore_WriteAndList(t *testing.T) {
	dir := t.TempDir()
	s := surfshark.NewConfigStore(dir)
	servers := []surfshark.Server{
		{ID: "us-nyc", Location: "New York", PubKey: "PUB1", Host: "1.2.3.4"},
		{ID: "fr-par", Location: "Paris", PubKey: "PUB2", Host: "5.6.7.8"},
	}
	if err := s.WriteAll(servers); err != nil {
		t.Fatal(err)
	}
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(list)
	if list[0] != "fr-par" || list[1] != "us-nyc" {
		t.Errorf("list = %v", list)
	}
}

func TestConfigStore_WriteAll_RemovesObsolete(t *testing.T) {
	dir := t.TempDir()
	s := surfshark.NewConfigStore(dir)
	s.WriteAll([]surfshark.Server{{ID: "us-nyc", PubKey: "P", Host: "1.1.1.1"}})
	s.WriteAll([]surfshark.Server{{ID: "fr-par", PubKey: "P", Host: "2.2.2.2"}})
	list, _ := s.List()
	if len(list) != 1 || list[0] != "fr-par" {
		t.Errorf("expected only fr-par, got %v", list)
	}
}

func TestConfigStore_RenderWG0Conf(t *testing.T) {
	dir := t.TempDir()
	s := surfshark.NewConfigStore(dir)
	if _, _, err := s.EnsureKeypair(); err != nil {
		t.Fatal(err)
	}
	s.WriteAll([]surfshark.Server{{ID: "us-nyc", PubKey: "PEERPUB", Host: "1.2.3.4"}})

	out := filepath.Join(dir, "wg0.conf")
	if err := s.RenderWG0Conf("us-nyc", out); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "[Interface]") {
		t.Error("missing [Interface]")
	}
	if !strings.Contains(string(data), "[Peer]") {
		t.Error("missing [Peer]")
	}
	if !strings.Contains(string(data), "PublicKey = PEERPUB") {
		t.Error("missing peer pub key")
	}
	if !strings.Contains(string(data), "Endpoint = 1.2.3.4:51820") {
		t.Errorf("missing endpoint, got:\n%s", string(data))
	}
	if strings.Contains(string(data), "DNS =") {
		t.Error("DNS = line must be stripped (per spec §6.3)")
	}
}

func TestConfigStore_RenderWG0Conf_UnknownLocation(t *testing.T) {
	dir := t.TempDir()
	s := surfshark.NewConfigStore(dir)
	s.EnsureKeypair()
	if err := s.RenderWG0Conf("nope", filepath.Join(dir, "wg0.conf")); err == nil {
		t.Fatal("expected error for unknown location")
	}
}
