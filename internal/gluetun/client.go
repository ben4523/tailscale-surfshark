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

type Settings struct {
	ServerSelection ServerSelection `json:"server_selection"`
}

type ServerSelection struct {
	Countries []string `json:"countries,omitempty"`
	Cities    []string `json:"cities,omitempty"`
	Regions   []string `json:"regions,omitempty"`
}

// SwitchCountry tells gluetun to reconnect to a server in the given country.
// gluetun reconciles the new settings by reconnecting under the hood.
func (c *Client) SwitchCountry(ctx context.Context, country string) error {
	settings := Settings{ServerSelection: ServerSelection{Countries: []string{country}}}
	return c.do(ctx, "PUT", "/v1/vpn/settings", settings, nil)
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
