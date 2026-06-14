package surfshark

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"
)

type ConfigStore struct {
	dir     string
	envPriv string // base64 private key supplied via env (preferred source)
}

func NewConfigStore(baseDir string) *ConfigStore {
	return &ConfigStore{dir: baseDir}
}

// SetEnvPrivateKey records a private key supplied via env (SURFSHARK_PRIVATE_KEY).
// When set, this overrides any local keypair generation: Surfshark's WG servers
// only accept keypairs registered on their account, so the operator must paste
// the private key they generated once via my.surfshark.com.
func (s *ConfigStore) SetEnvPrivateKey(b64 string) {
	s.envPriv = strings.TrimSpace(b64)
}

func (s *ConfigStore) keysDir() string    { return filepath.Join(s.dir, "keys") }
func (s *ConfigStore) configsDir() string { return filepath.Join(s.dir, "configs") }

// EnsureKeypair returns the WireGuard keypair (base64 priv, base64 pub).
// Preference order: env-provided private key -> on-disk keypair -> freshly generated.
// The "freshly generated" path is only useful for unit tests; in production
// Surfshark won't accept a key it doesn't know.
func (s *ConfigStore) EnsureKeypair() (priv, pub string, err error) {
	if s.envPriv != "" {
		p, perr := derivePublicKey(s.envPriv)
		if perr != nil {
			return "", "", fmt.Errorf("derive public key from SURFSHARK_PRIVATE_KEY: %w", perr)
		}
		return s.envPriv, p, nil
	}

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

func derivePublicKey(b64Priv string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Priv)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("private key must decode to 32 bytes, got %d", len(raw))
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// WriteAll caches one .json per server (keyed by Slug) and removes obsolete ones.
func (s *ConfigStore) WriteAll(servers []Server) error {
	if err := os.MkdirAll(s.configsDir(), 0o700); err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, srv := range servers {
		slug := srv.Slug()
		if slug == "" {
			continue
		}
		data, _ := json.MarshalIndent(srv, "", "  ")
		path := filepath.Join(s.configsDir(), slug+".json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return err
		}
		keep[slug+".json"] = true
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

func (s *ConfigStore) loadServer(slug string) (*Server, error) {
	data, err := os.ReadFile(filepath.Join(s.configsDir(), slug+".json"))
	if err != nil {
		return nil, err
	}
	var srv Server
	if err := json.Unmarshal(data, &srv); err != nil {
		return nil, err
	}
	return &srv, nil
}

// RenderWG0Conf writes a final wg0.conf at outPath for the given location slug
// and returns the resolved endpoint IPv4 (needed by the caller to install the
// /32 route exception that keeps WG-to-Surfshark traffic out of the wg0 tunnel).
//
// `Table = off` tells wg-quick NOT to install its own policy routing. The
// caller (main.go) installs the equivalent routes manually because Synology
// DSM doesn't let us write the src_valid_mark sysctl that wg-quick's default
// policy routing relies on.
//
// DNS line is intentionally omitted (see spec §6.3 — exit node uses public DNS).
//
// The ctx is honored for the DNS lookup of the peer endpoint, which is the
// only step here that does any I/O.
func (s *ConfigStore) RenderWG0Conf(slug, outPath string, ctx context.Context) (endpointIP string, err error) {
	srv, err := s.loadServer(slug)
	if err != nil {
		return "", fmt.Errorf("location %q not found in cache: %w", slug, err)
	}

	// Pre-resolve hostname → IPv4 so we have the literal address to install
	// the /32 exception route later. Also bypasses any DNS lookups that would
	// happen after we change the default route to wg0.
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIP(ctx, "ip4", srv.ConnectionName)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", srv.ConnectionName, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			endpointIP = v4.String()
			break
		}
	}
	if endpointIP == "" {
		return "", fmt.Errorf("no IPv4 for %s", srv.ConnectionName)
	}

	priv, _, err := s.EnsureKeypair()
	if err != nil {
		return "", err
	}
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.14.0.2/16
Table = off

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = %s:51820
PersistentKeepalive = 25
`, priv, srv.PubKey, endpointIP)
	if err := os.WriteFile(outPath, []byte(conf), 0o600); err != nil {
		return "", err
	}
	return endpointIP, nil
}
