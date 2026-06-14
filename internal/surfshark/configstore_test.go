package surfshark_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/surfshark"
)

// A known-good base64 WG private key (this one is just generated for test use).
const testPriv = "yAnzS6yQ1qjxlsR4cD0VmEgPm0BlHvfYI0XqA1mEnUE="

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

func TestConfigStore_EnvPrivateKey_TakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	s := surfshark.NewConfigStore(dir)
	s.SetEnvPrivateKey(testPriv)

	priv, pub, err := s.EnsureKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if priv != testPriv {
		t.Errorf("priv = %q, want env value", priv)
	}
	if pub == "" {
		t.Error("derived public key must not be empty")
	}
	// No on-disk key files should be written when using env key.
	if _, err := os.Stat(filepath.Join(dir, "keys", "wg-priv.key")); err == nil {
		t.Error("env mode must not persist private key to disk")
	}
}

func newServer(slug, pub string) surfshark.Server {
	return surfshark.Server{
		ConnectionName: slug + ".prod.surfshark.com",
		PubKey:         pub,
		Country:        "Testland",
		CountryCode:    "tl",
		Location:       "Test City",
	}
}

func TestConfigStore_WriteAndList_KeyedBySlug(t *testing.T) {
	dir := t.TempDir()
	s := surfshark.NewConfigStore(dir)
	servers := []surfshark.Server{
		newServer("us-nyc", "PUB1"),
		newServer("fr-par", "PUB2"),
	}
	if err := s.WriteAll(servers); err != nil {
		t.Fatal(err)
	}
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(list)
	if len(list) != 2 || list[0] != "fr-par" || list[1] != "us-nyc" {
		t.Errorf("list = %v", list)
	}
}

func TestConfigStore_WriteAll_RemovesObsolete(t *testing.T) {
	dir := t.TempDir()
	s := surfshark.NewConfigStore(dir)
	s.WriteAll([]surfshark.Server{newServer("us-nyc", "P")})
	s.WriteAll([]surfshark.Server{newServer("fr-par", "P")})
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
	s.WriteAll([]surfshark.Server{newServer("us-nyc", "PEERPUB")})

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
	if !strings.Contains(string(data), "Endpoint = us-nyc.prod.surfshark.com:51820") {
		t.Errorf("missing endpoint (must use ConnectionName), got:\n%s", string(data))
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
