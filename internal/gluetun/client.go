// Package gluetun wraps gluetun's HTTP control server.
// API docs: https://github.com/qdm12/gluetun-wiki/blob/main/setup/advanced/control-server.md
package gluetun

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	base string
	h    *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		base: strings.TrimRight(baseURL, "/"),
		h:    &http.Client{Timeout: 15 * time.Second},
	}
}

type Status struct {
	Status string `json:"status"` // "running" | "stopped"
}

func (c *Client) Status(ctx context.Context) (string, error) {
	var s Status
	if err := c.do(ctx, "GET", "/v1/openvpn/status", nil, &s); err != nil {
		return "", err
	}
	return s.Status, nil
}

// SetRunning toggles the VPN on/off without recreating gluetun.
func (c *Client) SetRunning(ctx context.Context, running bool) error {
	want := "stopped"
	if running {
		want = "running"
	}
	return c.do(ctx, "PUT", "/v1/openvpn/status", Status{Status: want}, nil)
}

// PatchSettings is the partial settings body PUT /v1/vpn/settings expects.
// Provider lives at the root of settings.VPN — NOT nested under openvpn.
// Nesting it under openvpn makes gluetun parse the openvpn section, ignore
// the unknown nested provider field, and return "settings left unchanged"
// silently. This cost us several hours of "why is it still Marseille".
type PatchSettings struct {
	Provider ProviderSection `json:"provider"`
}
type ProviderSection struct {
	ServerSelection ServerSelection `json:"server_selection"`
}
// No omitempty: PUT /v1/vpn/settings merges into existing settings, so we must
// send the fields explicitly to clear stale values. Empty slice = no constraint.
type ServerSelection struct {
	Countries []string `json:"countries"`
	Cities    []string `json:"cities"`
	Regions   []string `json:"regions,omitempty"`
}

// SwitchTarget sets countries+cities together. Both are sent explicitly to
// avoid gluetun's PUT-merge leaving a stale country (from the boot env var)
// constraining the new city filter — that combination intersects to zero
// matching servers, and gluetun silently falls back to a random server in
// the leftover country instead of the requested city.
func (c *Client) SwitchTarget(ctx context.Context, country, city string) error {
	countries := []string{}
	if country != "" {
		countries = []string{country}
	}
	cities := []string{}
	if city != "" {
		cities = []string{city}
	}
	body := PatchSettings{Provider: ProviderSection{
		ServerSelection: ServerSelection{Countries: countries, Cities: cities},
	}}
	return c.do(ctx, "PUT", "/v1/vpn/settings", body, nil)
}

func (c *Client) PublicIP(ctx context.Context) (string, error) {
	var out struct {
		PublicIP string `json:"public_ip"`
	}
	if err := c.do(ctx, "GET", "/v1/publicip/ip", nil, &out); err != nil {
		return "", err
	}
	return out.PublicIP, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var br io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		br = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, br)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.h.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, string(b))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
