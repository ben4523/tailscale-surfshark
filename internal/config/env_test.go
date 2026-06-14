package config_test

import (
	"strings"
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/config"
)

func TestLoad_MissingAuthkey(t *testing.T) {
	env := map[string]string{
		"TS_ALLOWED_USERS": "ben@example.com",
	}
	_, err := config.LoadFromMap(env)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "TS_AUTHKEY") {
		t.Fatalf("expected TS_AUTHKEY error, got: %v", err)
	}
}

func TestLoad_MissingAllowedUsers(t *testing.T) {
	env := map[string]string{
		"TS_AUTHKEY": "tskey-auth-abc",
	}
	_, err := config.LoadFromMap(env)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "TS_ALLOWED_USERS") {
		t.Fatalf("expected TS_ALLOWED_USERS error, got: %v", err)
	}
}

func TestLoad_Defaults(t *testing.T) {
	env := map[string]string{
		"TS_AUTHKEY":       "tskey-auth-abc",
		"TS_ALLOWED_USERS": "ben@example.com,alice@example.com",
	}
	c, err := config.LoadFromMap(env)
	if err != nil {
		t.Fatal(err)
	}
	if c.TSAuthkey != "tskey-auth-abc" {
		t.Errorf("authkey = %q", c.TSAuthkey)
	}
	if got, want := c.TSHostname, "synology-surfshark-exit"; got != want {
		t.Errorf("hostname = %q, want default %q", got, want)
	}
	if !c.KillSwitch {
		t.Error("KillSwitch must default to true")
	}
	if !c.Failover {
		t.Error("Failover must default to true")
	}
	if len(c.TSAllowedUsers) != 2 {
		t.Errorf("expected 2 allowed users, got %d", len(c.TSAllowedUsers))
	}
}

func TestLoad_KillSwitchFalse(t *testing.T) {
	env := map[string]string{
		"TS_AUTHKEY":       "k",
		"TS_ALLOWED_USERS": "ben@example.com",
		"KILL_SWITCH":      "false",
	}
	c, err := config.LoadFromMap(env)
	if err != nil {
		t.Fatal(err)
	}
	if c.KillSwitch {
		t.Error("KillSwitch should be false when env=false")
	}
}

func TestLoad_SurfsharkPrivateKey(t *testing.T) {
	env := map[string]string{
		"TS_AUTHKEY":            "k",
		"TS_ALLOWED_USERS":      "ben@example.com",
		"SURFSHARK_PRIVATE_KEY": "  yAnzS6yQ1qjxlsR4cD0VmEgPm0BlHvfYI0XqA1mEnUE=  ",
	}
	c, err := config.LoadFromMap(env)
	if err != nil {
		t.Fatal(err)
	}
	if c.SurfsharkPrivateKey != "yAnzS6yQ1qjxlsR4cD0VmEgPm0BlHvfYI0XqA1mEnUE=" {
		t.Errorf("private key not trimmed: %q", c.SurfsharkPrivateKey)
	}
}

func TestLoad_AllowedUserMembership(t *testing.T) {
	env := map[string]string{
		"TS_AUTHKEY":       "k",
		"TS_ALLOWED_USERS": "ben@example.com, alice@example.com",
	}
	c, _ := config.LoadFromMap(env)
	if !c.IsAllowed("ben@example.com") {
		t.Error("ben should be allowed")
	}
	if !c.IsAllowed("alice@example.com") {
		t.Error("alice should be allowed (trim whitespace)")
	}
	if c.IsAllowed("eve@example.com") {
		t.Error("eve should NOT be allowed")
	}
}
