package tailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, string(out))
	}
	return out, nil
}

type Client struct {
	r Runner
}

func New() *Client                   { return &Client{r: execRunner{}} }
func NewWithRunner(r Runner) *Client { return &Client{r: r} }

func (c *Client) IPv4(ctx context.Context) (string, error) {
	out, err := c.r.Run(ctx, "tailscale", "ip", "-4")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

type whoisOut struct {
	UserProfile struct {
		LoginName string `json:"LoginName"`
	} `json:"UserProfile"`
}

func (c *Client) Whois(ctx context.Context, ip string) (string, error) {
	out, err := c.r.Run(ctx, "tailscale", "whois", "--json", ip)
	if err != nil {
		return "", err
	}
	var w whoisOut
	if err := json.Unmarshal(out, &w); err != nil {
		return "", fmt.Errorf("decode whois: %w", err)
	}
	if w.UserProfile.LoginName == "" {
		return "", fmt.Errorf("no LoginName for %s", ip)
	}
	return w.UserProfile.LoginName, nil
}

type StatusSummary struct {
	BackendState string
	Hostname     string
	SelfIPv4     string
}

func (c *Client) Status(ctx context.Context) (*StatusSummary, error) {
	out, err := c.r.Run(ctx, "tailscale", "status", "--json")
	if err != nil {
		return nil, err
	}
	var raw struct {
		BackendState string `json:"BackendState"`
		Self         struct {
			HostName     string   `json:"HostName"`
			TailscaleIPs []string `json:"TailscaleIPs"`
		} `json:"Self"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	s := &StatusSummary{
		BackendState: raw.BackendState,
		Hostname:     raw.Self.HostName,
	}
	for _, ip := range raw.Self.TailscaleIPs {
		if !strings.Contains(ip, ":") {
			s.SelfIPv4 = ip
			break
		}
	}
	return s, nil
}
