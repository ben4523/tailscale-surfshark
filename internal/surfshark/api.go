// Package surfshark talks to Surfshark's public WireGuard cluster API.
//
// The login endpoint (POST /v1/auth/login) is gated by a Cloudflare bot
// challenge that a stock Go HTTP client cannot solve. The good news: the
// server cluster list is reachable WITHOUT authentication at
// GET https://api.surfshark.com/v4/server/clusters/generic.
//
// So we skip login entirely. The operator generates a WireGuard keypair
// once via https://my.surfshark.com/vpn/manual-setup/main/wireguard (one
// click) and supplies the private key via SURFSHARK_PRIVATE_KEY env var.
// The same keypair works against every Surfshark WG server.
//
// Response shape verified against api.surfshark.com on 2026-06-14.
package surfshark

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Server is one row from /v4/server/clusters/generic, kept minimal to the
// fields we actually use.
type Server struct {
	ID             string `json:"id"`             // UUID
	Country        string `json:"country"`        // "United States"
	CountryCode    string `json:"countryCode"`    // "us"
	Location       string `json:"location"`       // "New York"
	Region         string `json:"region"`         // "Americas"
	ConnectionName string `json:"connectionName"` // "us-nyc.prod.surfshark.com"
	PubKey         string `json:"pubKey"`         // peer pubkey (base64)
	Load           int    `json:"load"`
}

// Slug returns the human-friendly short ID derived from ConnectionName,
// e.g. "us-nyc.prod.surfshark.com" -> "us-nyc".
func (s Server) Slug() string {
	if i := strings.IndexByte(s.ConnectionName, '.'); i > 0 {
		return s.ConnectionName[:i]
	}
	return s.ConnectionName
}

// Display returns a label suitable for a dropdown, e.g. "us-nyc — New York, US".
func (s Server) Display() string {
	cc := strings.ToUpper(s.CountryCode)
	if s.Location != "" {
		return fmt.Sprintf("%s — %s, %s", s.Slug(), s.Location, cc)
	}
	return fmt.Sprintf("%s — %s", s.Slug(), cc)
}

type Client struct {
	base      string
	userAgent string
	h         *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		base:      strings.TrimRight(baseURL, "/"),
		userAgent: "SurfsharkLinux/1.4.5 (tailscale-surfshark)",
		h:         &http.Client{Timeout: 15 * time.Second},
	}
}

// ListServers returns all Surfshark "generic" WireGuard clusters. No auth.
func (c *Client) ListServers(ctx context.Context) ([]Server, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", c.base+"/v4/server/clusters/generic", nil)
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.h.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("list servers: HTTP %d", resp.StatusCode)
	}
	var servers []Server
	if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil {
		return nil, err
	}
	return servers, nil
}
