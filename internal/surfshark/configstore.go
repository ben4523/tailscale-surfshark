package surfshark

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"
)

type ConfigStore struct {
	dir string
}

func NewConfigStore(baseDir string) *ConfigStore {
	return &ConfigStore{dir: baseDir}
}

func (s *ConfigStore) keysDir() string    { return filepath.Join(s.dir, "keys") }
func (s *ConfigStore) configsDir() string { return filepath.Join(s.dir, "configs") }

// EnsureKeypair returns the WireGuard keypair (base64 priv, base64 pub).
// Creates one if it doesn't exist; reuses it on subsequent calls.
func (s *ConfigStore) EnsureKeypair() (priv, pub string, err error) {
	if err := os.MkdirAll(s.keysDir(), 0o700); err != nil {
		return "", "", err
	}
	privPath := filepath.Join(s.keysDir(), "wg-priv.key")
	pubPath := filepath.Join(s.keysDir(), "wg-pub.key")

	if pb, err := os.ReadFile(privPath); err == nil {
		pp, perr := os.ReadFile(pubPath)
		if perr == nil {
			return strings.TrimSpace(string(pb)), strings.TrimSpace(string(pp)), nil
		}
	}

	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return "", "", err
	}
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64
	pubKey, err := curve25519.X25519(privKey[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	priv = base64.StdEncoding.EncodeToString(privKey[:])
	pub = base64.StdEncoding.EncodeToString(pubKey)

	if err := os.WriteFile(privPath, []byte(priv+"\n"), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(pubPath, []byte(pub+"\n"), 0o600); err != nil {
		return "", "", err
	}
	return priv, pub, nil
}

// WriteAll caches one .json per server and removes obsolete ones.
func (s *ConfigStore) WriteAll(servers []Server) error {
	if err := os.MkdirAll(s.configsDir(), 0o700); err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, srv := range servers {
		data, _ := json.MarshalIndent(srv, "", "  ")
		path := filepath.Join(s.configsDir(), srv.ID+".json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return err
		}
		keep[srv.ID+".json"] = true
	}
	entries, _ := os.ReadDir(s.configsDir())
	for _, e := range entries {
		if !keep[e.Name()] {
			_ = os.Remove(filepath.Join(s.configsDir(), e.Name()))
		}
	}
	return nil
}

func (s *ConfigStore) List() ([]string, error) {
	entries, err := os.ReadDir(s.configsDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".json") {
			out = append(out, strings.TrimSuffix(name, ".json"))
		}
	}
	return out, nil
}

func (s *ConfigStore) loadServer(id string) (*Server, error) {
	data, err := os.ReadFile(filepath.Join(s.configsDir(), id+".json"))
	if err != nil {
		return nil, err
	}
	var srv Server
	if err := json.Unmarshal(data, &srv); err != nil {
		return nil, err
	}
	return &srv, nil
}

// RenderWG0Conf writes a final wg0.conf at outPath for the given location.
// DNS line is intentionally omitted (see spec §6.3 — exit node uses public DNS).
func (s *ConfigStore) RenderWG0Conf(locationID, outPath string) error {
	srv, err := s.loadServer(locationID)
	if err != nil {
		return fmt.Errorf("location %q not found in cache: %w", locationID, err)
	}
	priv, _, err := s.EnsureKeypair()
	if err != nil {
		return err
	}
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.14.0.2/16

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = %s:51820
PersistentKeepalive = 25
`, priv, srv.PubKey, srv.Host)
	return os.WriteFile(outPath, []byte(conf), 0o600)
}
