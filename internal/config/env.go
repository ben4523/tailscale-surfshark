package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	TSAuthkey         string
	TSHostname        string
	TSAllowedUsers    []string
	SurfsharkEmail    string
	SurfsharkPassword string
	KillSwitch        bool
	Failover          bool
}

func Load() (*Config, error) {
	env := map[string]string{}
	for _, k := range []string{
		"TS_AUTHKEY", "TS_HOSTNAME", "TS_ALLOWED_USERS",
		"SURFSHARK_EMAIL", "SURFSHARK_PASSWORD",
		"KILL_SWITCH", "FAILOVER",
	} {
		if v, ok := os.LookupEnv(k); ok {
			env[k] = v
		}
	}
	return LoadFromMap(env)
}

func LoadFromMap(env map[string]string) (*Config, error) {
	c := &Config{
		TSAuthkey:         env["TS_AUTHKEY"],
		TSHostname:        defaultStr(env["TS_HOSTNAME"], "synology-surfshark-exit"),
		SurfsharkEmail:    env["SURFSHARK_EMAIL"],
		SurfsharkPassword: env["SURFSHARK_PASSWORD"],
		KillSwitch:        parseBool(env["KILL_SWITCH"], true),
		Failover:          parseBool(env["FAILOVER"], true),
	}
	if c.TSAuthkey == "" {
		return nil, fmt.Errorf("TS_AUTHKEY is required")
	}
	users := strings.Split(env["TS_ALLOWED_USERS"], ",")
	for _, u := range users {
		u = strings.TrimSpace(u)
		if u != "" {
			c.TSAllowedUsers = append(c.TSAllowedUsers, u)
		}
	}
	if len(c.TSAllowedUsers) == 0 {
		return nil, fmt.Errorf("TS_ALLOWED_USERS is required (comma-separated tailnet emails)")
	}
	return c, nil
}

func (c *Config) IsAllowed(user string) bool {
	for _, u := range c.TSAllowedUsers {
		if strings.EqualFold(strings.TrimSpace(u), strings.TrimSpace(user)) {
			return true
		}
	}
	return false
}

func defaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func parseBool(v string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return def
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return def
	}
}
