// Package surfshark wraps the Surfshark account API for WireGuard provisioning.
//
// Surfshark does not publish an official API spec. The endpoints used here are
// based on the working assumption derived from community reverse-engineering work
// (see e.g. github.com/Wikinaut/surfshark-wireguard-cli). Endpoints to verify at
// integration time:
//
//   - POST /v1/auth/login                       {username, password} -> {token, renewToken}
//   - POST /v1/account/users/public-keys        {pubKey}             -> 200 (or 4xx with "already exists" treated as idempotent success)
//   - GET  /v4/server/clusters/generic                              -> []Server
//
// If Surfshark changes these paths, adjust here and update the spec accordingly.
package surfshark

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

type Server struct {
	ID             string `json:"id"`
	Country        string `json:"country"`
	CountryCode    string `json:"country_code"`
	Location       string `json:"location"`
	ConnectionName string `json:"connection_name"`
	PubKey         string `json:"pub_key"`
	Host           string `json:"host"`
}

type Client struct {
	base string
	h    *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		base: strings.TrimRight(baseURL, "/"),
		h:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) Login(ctx context.Context, user, pass string) (string, error) {
	body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	req, _ := http.NewRequestWithContext(ctx, "POST", c.base+"/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.h.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("login: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("login: empty token")
	}
	return out.Token, nil
}

func (c *Client) RegisterPubKey(ctx context.Context, token, pubKey string) error {
	body, _ := json.Marshal(map[string]string{"pubKey": pubKey})
	req, _ := http.NewRequestWithContext(ctx, "POST", c.base+"/v1/account/users/public-keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.h.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	b, _ := io.ReadAll(resp.Body)
	if strings.Contains(strings.ToLower(string(b)), "already exists") {
		return nil // idempotent
	}
	return fmt.Errorf("register pubkey: HTTP %d: %s", resp.StatusCode, string(b))
}

func (c *Client) ListServers(ctx context.Context, token string) ([]Server, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", c.base+"/v4/server/clusters/generic", nil)
	req.Header.Set("Authorization", "Bearer "+token)
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
