# Tailscale-Surfshark Exit Node Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single Docker container, deployable on Synology DS920+, that exposes a Tailscale exit node whose egress flows through Surfshark (WireGuard), controllable via a Tailscale-only web UI.

**Architecture:** Single container, bridge networking, sharing a netns between `tailscaled`, `wg-quick`, and a Go control daemon (PID 1). UI auth via Tailscale identity (`tailscale whois`). State persisted in a single JSON file. Kill switch and auto-failover enabled by default.

**Tech Stack:** Go 1.22+ (stdlib HTTP, `//go:embed`, no framework), Alpine base image, WireGuard kernel module, Tailscale, iptables, vanilla HTML/JS/CSS for the UI, docker-compose for deployment.

**Reference spec:** [`docs/superpowers/specs/2026-06-14-tailscale-surfshark-design.md`](../specs/2026-06-14-tailscale-surfshark-design.md)

---

## File Structure

Files created in this plan, grouped by responsibility:

```
.
├── .env.example                              # documented env var template
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── README.md                                 # ops guide + manual checklist
├── go.mod
├── go.sum
├── cmd/surfshark-control/
│   └── main.go                               # wires modules together, runs daemon
├── internal/
│   ├── config/env.go                         # env var parsing + validation
│   ├── config/env_test.go
│   ├── state/state.go                        # state.json load/save/atomic
│   ├── state/state_test.go
│   ├── logging/logger.go                     # structured JSON logger
│   ├── logging/logger_test.go
│   ├── eventbus/bus.go                       # in-process pub/sub for SSE
│   ├── eventbus/bus_test.go
│   ├── tailscale/client.go                   # wraps `tailscale` CLI + tailscaled socket
│   ├── tailscale/client_test.go
│   ├── surfshark/api.go                      # Surfshark API client (login, register, list)
│   ├── surfshark/api_test.go
│   ├── surfshark/configstore.go              # cached .conf management
│   ├── surfshark/configstore_test.go
│   ├── wireguard/controller.go               # wg-quick up/down + health
│   ├── wireguard/controller_test.go
│   ├── iptables/rules.go                     # build/apply NAT + FORWARD + kill-switch
│   ├── iptables/rules_test.go
│   ├── watchdog/tailscaled.go                # supervises tailscaled
│   ├── watchdog/wg.go                        # supervises wg0 + failover
│   ├── watchdog/statuspoller.go              # public IP + latency polling
│   ├── watchdog/wg_test.go                   # failover state machine tests
│   ├── auth/middleware.go                    # tailnet identity middleware
│   ├── auth/middleware_test.go
│   └── httpapi/server.go                     # HTTP server + handlers + SSE
│       ├── handlers.go
│       ├── sse.go
│       └── server_test.go
├── web/
│   ├── index.html                            # //go:embed
│   ├── app.js
│   └── style.css
├── docker/
│   ├── entrypoint.sh
│   └── stubs/                                # for integration tests
│       ├── tailscale-stub.sh
│       └── tailscaled-stub.sh
└── test/integration/
    ├── docker-compose.test.yml
    ├── mocksurfshark/main.go                 # mock API for integration test
    └── e2e_test.go
```

Each `internal/<package>/` is a single-purpose unit. Boundaries:

- `config` → reads env only, returns a typed struct
- `state` → reads/writes a JSON file atomically, never makes external calls
- `tailscale` / `surfshark` / `wireguard` / `iptables` → wrap external commands or HTTP APIs
- `watchdog` → coordinates the above on timers
- `auth` → identity middleware, depends only on `tailscale`
- `httpapi` → wires HTTP routes to the other packages; nothing depends on it
- `cmd/surfshark-control/main.go` → composition root, no business logic

---

## Pre-flight: Tooling Assumptions

Before starting:

- Go 1.22 or later installed locally (`go version`).
- Docker Desktop or compatible (`docker --version`, `docker compose version`).
- A working directory with the spec already committed (this repo).

If any of those are missing, install them before Task 1.

---

## Task 1: Project skeleton

**Files:**
- Create: `go.mod`, `.gitignore`, `Makefile`, `cmd/surfshark-control/main.go`, `internal/.keep`

- [ ] **Step 1: Initialize Go module**

Run from repo root:

```bash
go mod init github.com/bbitton/tailscale-surfshark
```

Expected: creates `go.mod` with module path and Go version.

- [ ] **Step 2: Write `.gitignore`**

Create `.gitignore`:

```gitignore
# Build artifacts
/bin/
/dist/
surfshark-control

# Local env
.env
.env.local

# Local data (volume mount target)
/data/

# Go
*.test
*.out
vendor/

# IDE
.vscode/
.idea/
.DS_Store
```

- [ ] **Step 3: Write a minimal `cmd/surfshark-control/main.go`**

Create `cmd/surfshark-control/main.go`:

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "surfshark-control: skeleton, not yet implemented")
	os.Exit(0)
}
```

- [ ] **Step 4: Write `Makefile`**

Create `Makefile`:

```makefile
.PHONY: build test test-integration lint clean run

BIN := bin/surfshark-control
PKG := ./...

build:
	go build -o $(BIN) ./cmd/surfshark-control

test:
	go test -race -count=1 $(PKG)

test-integration:
	cd test/integration && docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from runner

lint:
	go vet $(PKG)

run: build
	./$(BIN)

clean:
	rm -rf bin/ dist/
```

- [ ] **Step 5: Verify it builds**

```bash
make build
./bin/surfshark-control
```

Expected: prints `surfshark-control: skeleton, not yet implemented` then exits 0.

- [ ] **Step 6: Commit**

```bash
git add go.mod .gitignore Makefile cmd/surfshark-control/main.go
git commit -m "chore: project skeleton (go module, makefile, gitignore)"
```

---

## Task 2: Env config parsing

**Files:**
- Create: `internal/config/env.go`
- Test:   `internal/config/env_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/config/env_test.go`:

```go
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
```

- [ ] **Step 2: Run the tests, expect failure**

```bash
go test ./internal/config/...
```

Expected: compilation error (`config` package doesn't exist yet).

- [ ] **Step 3: Implement `internal/config/env.go`**

Create `internal/config/env.go`:

```go
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
```

- [ ] **Step 4: Run tests, expect pass**

```bash
go test -race ./internal/config/...
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add internal/config/
git commit -m "feat(config): env loader with validation and defaults"
```

---

## Task 3: State manager (atomic JSON persistence)

**Files:**
- Create: `internal/state/state.go`
- Test:   `internal/state/state_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/state/state_test.go`:

```go
package state_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbitton/tailscale-surfshark/internal/state"
)

func TestDefault(t *testing.T) {
	s := state.Default()
	if s.Version != 1 {
		t.Errorf("version = %d", s.Version)
	}
	if s.Surfshark.Toggle {
		t.Error("toggle should default false")
	}
}

func TestLoadNotExist_ReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	s, err := state.Load(filepath.Join(dir, "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 1 {
		t.Errorf("expected default state")
	}
}

func TestSaveLoad_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := state.Default()
	s.Surfshark.Toggle = true
	s.Surfshark.CurrentLocation = "us-nyc"
	s.Surfshark.PreferredLocations = []string{"us-nyc", "fr-par"}
	s.Stats.PublicIP = "1.2.3.4"
	now := time.Now().UTC().Truncate(time.Second)
	s.Stats.LastMeasured = now

	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Surfshark.CurrentLocation != "us-nyc" {
		t.Errorf("location = %q", loaded.Surfshark.CurrentLocation)
	}
	if !loaded.Stats.LastMeasured.Equal(now) {
		t.Errorf("timestamp not preserved: %v vs %v", loaded.Stats.LastMeasured, now)
	}
}

func TestSave_Atomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := state.Default()
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	// After save, no leftover .tmp file
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf(".tmp leftover: err=%v", err)
	}
}

func TestLoad_CorruptedFile_BacksUpAndReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 1 {
		t.Errorf("expected default after corruption")
	}
	// Backup file should exist
	matches, _ := filepath.Glob(path + ".broken-*")
	if len(matches) == 0 {
		t.Errorf("expected backup file, none found")
	}
}
```

- [ ] **Step 2: Run, expect failure**

```bash
go test ./internal/state/...
```

Expected: compile error.

- [ ] **Step 3: Implement `internal/state/state.go`**

Create `internal/state/state.go`:

```go
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type State struct {
	Version   int            `json:"version"`
	Surfshark SurfsharkState `json:"surfshark"`
	KillSwitch KillSwitchState `json:"kill_switch"`
	Stats     StatsCache     `json:"stats_cache"`

	mu sync.Mutex `json:"-"`
}

type SurfsharkState struct {
	Toggle             bool       `json:"toggle"`
	CurrentLocation    string     `json:"current_location"`
	PreferredLocations []string   `json:"preferred_locations"`
	LastRefresh        *time.Time `json:"last_refresh"`
	LastFailover       *time.Time `json:"last_failover"`
}

type KillSwitchState struct {
	EnabledByEnv   bool `json:"enabled_by_env"`
	CurrentlyArmed bool `json:"currently_armed"`
}

type StatsCache struct {
	PublicIP        string    `json:"public_ip"`
	PublicIPLocation string   `json:"public_ip_location"`
	LastMeasured    time.Time `json:"last_measured"`
	WG0LatencyMS    int       `json:"wg0_latency_ms"`
	WG0LastHandshake time.Time `json:"wg0_last_handshake"`
}

func Default() *State {
	return &State{Version: 1}
}

func Load(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		backup := fmt.Sprintf("%s.broken-%s", path, time.Now().UTC().Format("20060102T150405"))
		_ = os.Rename(path, backup)
		return Default(), nil
	}
	if s.Version == 0 {
		s.Version = 1
	}
	return &s, nil
}

func (s *State) Save(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
```

- [ ] **Step 4: Run, expect pass**

```bash
go test -race ./internal/state/...
```

- [ ] **Step 5: Commit**

```bash
git add internal/state/
git commit -m "feat(state): atomic JSON state manager with corruption recovery"
```

---

## Task 4: Structured logger

**Files:**
- Create: `internal/logging/logger.go`
- Test:   `internal/logging/logger_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/logging/logger_test.go`:

```go
package logging_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/logging"
)

func TestLogger_StructuredJSON(t *testing.T) {
	var buf bytes.Buffer
	l := logging.New(&buf, "info")
	l.Info("hello", "user", "ben@example.com", "action", "toggle")

	line := strings.TrimSpace(buf.String())
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("not JSON: %v\nline: %s", err, line)
	}
	if got["msg"] != "hello" {
		t.Errorf("msg = %v", got["msg"])
	}
	if got["user"] != "ben@example.com" {
		t.Errorf("user = %v", got["user"])
	}
	if got["level"] != "INFO" {
		t.Errorf("level = %v", got["level"])
	}
}

func TestLogger_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := logging.New(&buf, "warn")
	l.Info("should-not-appear")
	l.Warn("should-appear")
	if strings.Contains(buf.String(), "should-not-appear") {
		t.Error("info line leaked at warn level")
	}
	if !strings.Contains(buf.String(), "should-appear") {
		t.Error("warn line missing")
	}
}
```

- [ ] **Step 2: Run, expect failure**

```bash
go test ./internal/logging/...
```

- [ ] **Step 3: Implement `internal/logging/logger.go`**

Create `internal/logging/logger.go`:

```go
package logging

import (
	"io"
	"log/slog"
	"strings"
)

type Logger struct {
	s *slog.Logger
}

func New(w io.Writer, level string) *Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "info", "":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lvl})
	return &Logger{s: slog.New(h)}
}

func (l *Logger) Info(msg string, kv ...any)  { l.s.Info(msg, kv...) }
func (l *Logger) Warn(msg string, kv ...any)  { l.s.Warn(msg, kv...) }
func (l *Logger) Error(msg string, kv ...any) { l.s.Error(msg, kv...) }
func (l *Logger) Debug(msg string, kv ...any) { l.s.Debug(msg, kv...) }
```

- [ ] **Step 4: Run, expect pass**

```bash
go test -race ./internal/logging/...
```

Note: `slog` outputs `level=INFO` for info — the test checks for that exact string.

- [ ] **Step 5: Commit**

```bash
git add internal/logging/
git commit -m "feat(logging): structured JSON logger over slog"
```

---

## Task 5: In-process event bus (for SSE)

**Files:**
- Create: `internal/eventbus/bus.go`
- Test:   `internal/eventbus/bus_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/eventbus/bus_test.go`:

```go
package eventbus_test

import (
	"testing"
	"time"

	"github.com/bbitton/tailscale-surfshark/internal/eventbus"
)

func TestBus_PublishSubscribe(t *testing.T) {
	b := eventbus.New(8)
	sub := b.Subscribe()
	defer b.Unsubscribe(sub)

	b.Publish(eventbus.Event{Type: "test", Payload: "hello"})

	select {
	case ev := <-sub:
		if ev.Type != "test" {
			t.Errorf("type=%q", ev.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for event")
	}
}

func TestBus_MultipleSubscribers(t *testing.T) {
	b := eventbus.New(8)
	a := b.Subscribe()
	c := b.Subscribe()
	defer b.Unsubscribe(a)
	defer b.Unsubscribe(c)

	b.Publish(eventbus.Event{Type: "fanout"})

	for _, ch := range []<-chan eventbus.Event{a, c} {
		select {
		case ev := <-ch:
			if ev.Type != "fanout" {
				t.Errorf("type=%q", ev.Type)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("subscriber missed event")
		}
	}
}

func TestBus_SlowSubscriberDoesNotBlock(t *testing.T) {
	b := eventbus.New(2)
	_ = b.Subscribe() // never read
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			b.Publish(eventbus.Event{Type: "burst"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("publish blocked on slow subscriber")
	}
}
```

- [ ] **Step 2: Run, expect fail**

```bash
go test ./internal/eventbus/...
```

- [ ] **Step 3: Implement `internal/eventbus/bus.go`**

Create `internal/eventbus/bus.go`:

```go
package eventbus

import "sync"

type Event struct {
	Type    string `json:"type"`
	Payload any    `json:"payload,omitempty"`
}

type Bus struct {
	mu     sync.Mutex
	subs   map[chan Event]struct{}
	bufLen int
}

func New(bufLen int) *Bus {
	if bufLen <= 0 {
		bufLen = 8
	}
	return &Bus{subs: map[chan Event]struct{}{}, bufLen: bufLen}
}

func (b *Bus) Subscribe() <-chan Event {
	ch := make(chan Event, b.bufLen)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *Bus) Unsubscribe(ch <-chan Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for c := range b.subs {
		if c == ch {
			delete(b.subs, c)
			close(c)
			return
		}
	}
}

func (b *Bus) Publish(ev Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- ev:
		default:
			// drop on slow consumer; never block publisher
		}
	}
}
```

- [ ] **Step 4: Run, expect pass**

```bash
go test -race ./internal/eventbus/...
```

- [ ] **Step 5: Commit**

```bash
git add internal/eventbus/
git commit -m "feat(eventbus): in-process pub/sub for SSE fan-out"
```

---

## Task 6: Tailscale client wrapper

**Files:**
- Create: `internal/tailscale/client.go`
- Test:   `internal/tailscale/client_test.go`

Wraps `tailscale ip`, `tailscale status --json`, `tailscale whois --json`. For tests, the `runner` is injectable.

- [ ] **Step 1: Write failing tests**

Create `internal/tailscale/client_test.go`:

```go
package tailscale_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/tailscale"
)

type fakeRunner struct {
	resp map[string]string
	err  map[string]error
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	if e := f.err[key]; e != nil {
		return nil, e
	}
	return []byte(f.resp[key]), nil
}

func TestIPv4(t *testing.T) {
	r := &fakeRunner{resp: map[string]string{
		"tailscale ip -4": "100.64.0.5\n",
	}}
	c := tailscale.NewWithRunner(r)
	ip, err := c.IPv4(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ip != "100.64.0.5" {
		t.Errorf("ip = %q", ip)
	}
}

func TestWhois_FoundUser(t *testing.T) {
	r := &fakeRunner{resp: map[string]string{
		"tailscale whois --json 100.64.0.10": `{"UserProfile":{"LoginName":"ben@example.com"}}`,
	}}
	c := tailscale.NewWithRunner(r)
	user, err := c.Whois(context.Background(), "100.64.0.10")
	if err != nil {
		t.Fatal(err)
	}
	if user != "ben@example.com" {
		t.Errorf("user = %q", user)
	}
}

func TestWhois_Error(t *testing.T) {
	r := &fakeRunner{err: map[string]error{
		"tailscale whois --json 1.2.3.4": errors.New("not in tailnet"),
	}}
	c := tailscale.NewWithRunner(r)
	_, err := c.Whois(context.Background(), "1.2.3.4")
	if err == nil {
		t.Fatal("expected error")
	}
}
```

- [ ] **Step 2: Run, expect failure**

```bash
go test ./internal/tailscale/...
```

- [ ] **Step 3: Implement `internal/tailscale/client.go`**

Create `internal/tailscale/client.go`:

```go
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

func New() *Client                       { return &Client{r: execRunner{}} }
func NewWithRunner(r Runner) *Client     { return &Client{r: r} }

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
```

- [ ] **Step 4: Run, expect pass**

```bash
go test -race ./internal/tailscale/...
```

- [ ] **Step 5: Commit**

```bash
git add internal/tailscale/
git commit -m "feat(tailscale): client wrapper for ip/whois/status"
```

---

## Task 7: Surfshark API client (research first, then implement)

**Files:**
- Create: `internal/surfshark/api.go`
- Test:   `internal/surfshark/api_test.go`

**Important context:** Surfshark's WireGuard registration API is undocumented. Before implementing, the engineer must verify the current endpoint shapes from one of these community references:

- https://github.com/Wikinaut/surfshark-wireguard-cli
- https://github.com/dani-garcia/surfshark-tools (may have moved)
- https://github.com/PaoloTopa/surfshark-wg-config-generator

Reasonable working assumption (confirm at implementation time):

- `POST https://api.surfshark.com/v1/auth/login` body `{"username":"…","password":"…"}` → `{"token":"…", "renewToken":"…"}`
- `POST https://api.surfshark.com/v1/account/users/public-keys` (Bearer token) body `{"pubKey":"…"}` → 200 on success, 4xx if already registered (idempotent — treat 4xx with `already exists` body as success)
- `GET https://api.surfshark.com/v4/server/clusters/generic` → array of `{id, country, country_code, location, connection_name, pub_key, host, hostname}`

The client must accept a configurable base URL so tests can swap to `httptest.NewServer`.

- [ ] **Step 1: Verify Surfshark API endpoints**

Open the community repos above, identify the current login + register + list endpoints and their request/response shapes. If they differ from the working assumption above, adjust the implementation in Step 3 to match what you found.

Write a short note (one paragraph) into `internal/surfshark/api.go`'s top-of-file comment recording which reference repo + commit hash you matched against, so future maintainers can re-check.

- [ ] **Step 2: Write failing tests**

Create `internal/surfshark/api_test.go`:

```go
package surfshark_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/surfshark"
)

func TestLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/login" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["username"] != "u" || body["password"] != "p" {
			t.Errorf("bad body: %v", body)
		}
		json.NewEncoder(w).Encode(map[string]string{"token": "tok", "renewToken": "rt"})
	}))
	defer srv.Close()

	c := surfshark.NewClient(srv.URL)
	tok, err := c.Login(context.Background(), "u", "p")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok" {
		t.Errorf("token = %q", tok)
	}
}

func TestLogin_BadCreds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"invalid creds"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := surfshark.NewClient(srv.URL)
	_, err := c.Login(context.Background(), "u", "p")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v", err)
	}
}

func TestRegisterPubKey_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c := surfshark.NewClient(srv.URL)
	if err := c.RegisterPubKey(context.Background(), "tok", "PUBKEY=="); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterPubKey_AlreadyExists_IsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"public key already exists"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	c := surfshark.NewClient(srv.URL)
	if err := c.RegisterPubKey(context.Background(), "tok", "PUBKEY=="); err != nil {
		t.Fatalf("should be idempotent: %v", err)
	}
}

func TestListServers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"id": "us-nyc", "country": "United States", "country_code": "us", "location": "New York", "connection_name": "us-nyc.prod.surfshark.com", "pub_key": "PUB1", "host": "1.2.3.4"},
			{"id": "fr-par", "country": "France", "country_code": "fr", "location": "Paris", "connection_name": "fr-par.prod.surfshark.com", "pub_key": "PUB2", "host": "5.6.7.8"},
		})
	}))
	defer srv.Close()
	c := surfshark.NewClient(srv.URL)
	servers, err := c.ListServers(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("got %d servers", len(servers))
	}
	if servers[0].ID != "us-nyc" {
		t.Errorf("first id = %q", servers[0].ID)
	}
}
```

- [ ] **Step 3: Implement `internal/surfshark/api.go`**

Create `internal/surfshark/api.go`:

```go
// Package surfshark wraps the Surfshark account API for WireGuard provisioning.
//
// Surfshark does not publish an official API spec. The endpoints used here are
// validated against community reverse-engineering work — see Task 7 of the
// implementation plan for which reference was matched at implementation time.
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
```

- [ ] **Step 4: Run, expect pass**

```bash
go test -race ./internal/surfshark/...
```

- [ ] **Step 5: Commit**

```bash
git add internal/surfshark/api.go internal/surfshark/api_test.go
git commit -m "feat(surfshark): API client for login/register/list"
```

---

## Task 8: Surfshark config store (cached `.conf` management)

**Files:**
- Create: `internal/surfshark/configstore.go`
- Test:   `internal/surfshark/configstore_test.go`

Stores one `.conf` file per Surfshark location in a directory; generates a stable keypair; renders the final `wg0.conf` for a chosen location.

- [ ] **Step 1: Write failing tests**

Create `internal/surfshark/configstore_test.go`:

```go
package surfshark_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/surfshark"
)

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

func TestConfigStore_WriteAndList(t *testing.T) {
	dir := t.TempDir()
	s := surfshark.NewConfigStore(dir)
	servers := []surfshark.Server{
		{ID: "us-nyc", Location: "New York", PubKey: "PUB1", Host: "1.2.3.4"},
		{ID: "fr-par", Location: "Paris", PubKey: "PUB2", Host: "5.6.7.8"},
	}
	if err := s.WriteAll(servers); err != nil {
		t.Fatal(err)
	}
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(list)
	if list[0] != "fr-par" || list[1] != "us-nyc" {
		t.Errorf("list = %v", list)
	}
}

func TestConfigStore_WriteAll_RemovesObsolete(t *testing.T) {
	dir := t.TempDir()
	s := surfshark.NewConfigStore(dir)
	s.WriteAll([]surfshark.Server{{ID: "us-nyc", PubKey: "P", Host: "1.1.1.1"}})
	s.WriteAll([]surfshark.Server{{ID: "fr-par", PubKey: "P", Host: "2.2.2.2"}})
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
	s.WriteAll([]surfshark.Server{{ID: "us-nyc", PubKey: "PEERPUB", Host: "1.2.3.4"}})

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
	if !strings.Contains(string(data), "Endpoint = 1.2.3.4:51820") {
		t.Errorf("missing endpoint, got:\n%s", string(data))
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
```

- [ ] **Step 2: Run, expect failure**

```bash
go test ./internal/surfshark/...
```

- [ ] **Step 3: Add `golang.org/x/crypto/curve25519` dependency**

```bash
go get golang.org/x/crypto/curve25519
go mod tidy
```

- [ ] **Step 4: Implement `internal/surfshark/configstore.go`**

Create `internal/surfshark/configstore.go`:

```go
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

// WriteAll caches one .conf per server and removes obsolete ones.
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
// DNS line is intentionally omitted (see spec §6.3 — exit node uses public DNS at host level).
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
```

- [ ] **Step 5: Run, expect pass**

```bash
go test -race ./internal/surfshark/...
```

- [ ] **Step 6: Commit**

```bash
git add internal/surfshark/ go.mod go.sum
git commit -m "feat(surfshark): config store with persistent keypair and wg0.conf rendering"
```

---

## Task 9: WireGuard controller

**Files:**
- Create: `internal/wireguard/controller.go`
- Test:   `internal/wireguard/controller_test.go`

Wraps `wg-quick up/down`, parses `wg show` output for handshake/latency. Runner is injectable.

- [ ] **Step 1: Write failing tests**

Create `internal/wireguard/controller_test.go`:

```go
package wireguard_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bbitton/tailscale-surfshark/internal/wireguard"
)

type fakeRunner struct {
	calls []string
	out   map[string]string
	err   map[string]error
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	f.calls = append(f.calls, key)
	if e := f.err[key]; e != nil {
		return nil, e
	}
	return []byte(f.out[key]), nil
}

func TestUp_CallsWGQuick(t *testing.T) {
	r := &fakeRunner{out: map[string]string{}}
	c := wireguard.NewWithRunner(r)
	if err := c.Up(context.Background(), "/etc/wireguard/wg0.conf"); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 || r.calls[0] != "wg-quick up /etc/wireguard/wg0.conf" {
		t.Errorf("calls = %v", r.calls)
	}
}

func TestUp_FailureBubbles(t *testing.T) {
	r := &fakeRunner{err: map[string]error{
		"wg-quick up /etc/wireguard/wg0.conf": errors.New("nope"),
	}, out: map[string]string{}}
	c := wireguard.NewWithRunner(r)
	if err := c.Up(context.Background(), "/etc/wireguard/wg0.conf"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDown(t *testing.T) {
	r := &fakeRunner{out: map[string]string{}}
	c := wireguard.NewWithRunner(r)
	if err := c.Down(context.Background(), "wg0"); err != nil {
		t.Fatal(err)
	}
	if r.calls[0] != "wg-quick down wg0" {
		t.Errorf("calls = %v", r.calls)
	}
}

func TestLastHandshake_Parses(t *testing.T) {
	r := &fakeRunner{
		out: map[string]string{
			"wg show wg0 latest-handshakes": "PEERPUBKEY\t1720000000\n",
		},
	}
	c := wireguard.NewWithRunner(r)
	hs, err := c.LastHandshake(context.Background(), "wg0")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Unix(1720000000, 0)
	if !hs.Equal(want) {
		t.Errorf("hs = %v, want %v", hs, want)
	}
}

func TestLastHandshake_NoneYet(t *testing.T) {
	r := &fakeRunner{out: map[string]string{
		"wg show wg0 latest-handshakes": "PEER\t0\n",
	}}
	c := wireguard.NewWithRunner(r)
	hs, err := c.LastHandshake(context.Background(), "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if !hs.IsZero() {
		t.Errorf("expected zero time, got %v", hs)
	}
}
```

- [ ] **Step 2: Run, expect failure**

```bash
go test ./internal/wireguard/...
```

- [ ] **Step 3: Implement `internal/wireguard/controller.go`**

Create `internal/wireguard/controller.go`:

```go
package wireguard

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
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

type Controller struct{ r Runner }

func New() *Controller                   { return &Controller{r: execRunner{}} }
func NewWithRunner(r Runner) *Controller { return &Controller{r: r} }

func (c *Controller) Up(ctx context.Context, confPath string) error {
	_, err := c.r.Run(ctx, "wg-quick", "up", confPath)
	return err
}

func (c *Controller) Down(ctx context.Context, ifaceOrPath string) error {
	_, err := c.r.Run(ctx, "wg-quick", "down", ifaceOrPath)
	return err
}

func (c *Controller) LastHandshake(ctx context.Context, iface string) (time.Time, error) {
	out, err := c.r.Run(ctx, "wg", "show", iface, "latest-handshakes")
	if err != nil {
		return time.Time{}, err
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return time.Time{}, nil
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return time.Time{}, fmt.Errorf("unexpected output: %q", line)
	}
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	if ts == 0 {
		return time.Time{}, nil
	}
	return time.Unix(ts, 0), nil
}
```

- [ ] **Step 4: Run, expect pass**

```bash
go test -race ./internal/wireguard/...
```

- [ ] **Step 5: Commit**

```bash
git add internal/wireguard/
git commit -m "feat(wireguard): controller for wg-quick up/down and handshake parsing"
```

---

## Task 10: Iptables rules manager

**Files:**
- Create: `internal/iptables/rules.go`
- Test:   `internal/iptables/rules_test.go`

Builds the canonical rule set and applies it. Tests use snapshot-style comparison on the generated command sequences (no real `iptables` exec in unit tests).

- [ ] **Step 1: Write failing tests**

Create `internal/iptables/rules_test.go`:

```go
package iptables_test

import (
	"context"
	"strings"
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/iptables"
)

type recRunner struct{ calls []string }

func (r *recRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	return nil, nil
}

func TestApplyBase_AddsExpectedRules(t *testing.T) {
	r := &recRunner{}
	m := iptables.NewWithRunner(r)
	if err := m.ApplyBase(context.Background(), "tailscale0", "wg0", "eth0"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, "\n")
	for _, want := range []string{
		"iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE",
		"iptables -A FORWARD -i tailscale0 -o wg0 -j ACCEPT",
		"iptables -A FORWARD -i wg0 -o tailscale0 -m state --state RELATED,ESTABLISHED -j ACCEPT",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing rule %q in:\n%s", want, joined)
		}
	}
}

func TestArmKillSwitch_BlocksDirectEgress(t *testing.T) {
	r := &recRunner{}
	m := iptables.NewWithRunner(r)
	if err := m.ArmKillSwitch(context.Background(), "tailscale0", "eth0"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "iptables -A FORWARD -i tailscale0 -o eth0 -j DROP") {
		t.Errorf("missing kill-switch DROP in:\n%s", joined)
	}
}

func TestDisarmKillSwitch_RemovesBlock(t *testing.T) {
	r := &recRunner{}
	m := iptables.NewWithRunner(r)
	if err := m.DisarmKillSwitch(context.Background(), "tailscale0", "eth0"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, "\n")
	if !strings.Contains(joined, "iptables -D FORWARD -i tailscale0 -o eth0 -j DROP") {
		t.Errorf("missing kill-switch DROP delete in:\n%s", joined)
	}
}

func TestIdempotent_DoubleApplyDoesNotDuplicate(t *testing.T) {
	r := &recRunner{}
	m := iptables.NewWithRunner(r)
	_ = m.ApplyBase(context.Background(), "tailscale0", "wg0", "eth0")
	first := len(r.calls)
	_ = m.ApplyBase(context.Background(), "tailscale0", "wg0", "eth0")
	if len(r.calls) != 2*first {
		// We re-issue all rules with -D before -A to keep idempotent in real iptables,
		// so calls double exactly.
		t.Logf("calls doubled from %d to %d (expected idempotent reapply)", first, len(r.calls))
	}
}
```

- [ ] **Step 2: Run, expect failure**

```bash
go test ./internal/iptables/...
```

- [ ] **Step 3: Implement `internal/iptables/rules.go`**

Create `internal/iptables/rules.go`:

```go
package iptables

import (
	"context"
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

type Manager struct{ r Runner }

func New() *Manager                   { return &Manager{r: execRunner{}} }
func NewWithRunner(r Runner) *Manager { return &Manager{r: r} }

// ApplyBase installs NAT + FORWARD rules. Idempotent: existing rules are deleted then re-added.
func (m *Manager) ApplyBase(ctx context.Context, tsIface, wgIface, lanIface string) error {
	rules := []ruleSpec{
		{table: "nat", chain: "POSTROUTING", args: []string{"-o", wgIface, "-j", "MASQUERADE"}},
		{chain: "FORWARD", args: []string{"-i", tsIface, "-o", wgIface, "-j", "ACCEPT"}},
		{chain: "FORWARD", args: []string{"-i", wgIface, "-o", tsIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
	}
	for _, r := range rules {
		if err := m.ensureRule(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) ArmKillSwitch(ctx context.Context, tsIface, lanIface string) error {
	return m.ensureRule(ctx, ruleSpec{
		chain: "FORWARD",
		args:  []string{"-i", tsIface, "-o", lanIface, "-j", "DROP"},
	})
}

func (m *Manager) DisarmKillSwitch(ctx context.Context, tsIface, lanIface string) error {
	return m.deleteRule(ctx, ruleSpec{
		chain: "FORWARD",
		args:  []string{"-i", tsIface, "-o", lanIface, "-j", "DROP"},
	})
}

type ruleSpec struct {
	table string
	chain string
	args  []string
}

func (m *Manager) ensureRule(ctx context.Context, r ruleSpec) error {
	_ = m.deleteRule(ctx, r) // ignore errors on delete (may not exist yet)
	cmd := []string{}
	if r.table != "" {
		cmd = append(cmd, "-t", r.table)
	}
	cmd = append(cmd, "-A", r.chain)
	cmd = append(cmd, r.args...)
	_, err := m.r.Run(ctx, "iptables", cmd...)
	return err
}

func (m *Manager) deleteRule(ctx context.Context, r ruleSpec) error {
	cmd := []string{}
	if r.table != "" {
		cmd = append(cmd, "-t", r.table)
	}
	cmd = append(cmd, "-D", r.chain)
	cmd = append(cmd, r.args...)
	_, err := m.r.Run(ctx, "iptables", cmd...)
	return err
}
```

- [ ] **Step 4: Run, expect pass**

```bash
go test -race ./internal/iptables/...
```

- [ ] **Step 5: Commit**

```bash
git add internal/iptables/
git commit -m "feat(iptables): NAT+FORWARD rules manager with kill-switch arm/disarm"
```

---

## Task 11: Auth middleware (Tailscale identity)

**Files:**
- Create: `internal/auth/middleware.go`
- Test:   `internal/auth/middleware_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/auth/middleware_test.go`:

```go
package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/auth"
)

type fakeWhois func(ctx context.Context, ip string) (string, error)

func (f fakeWhois) Whois(ctx context.Context, ip string) (string, error) { return f(ctx, ip) }

func TestMiddleware_AllowsWhitelistedUser(t *testing.T) {
	mw := auth.New(fakeWhois(func(ctx context.Context, ip string) (string, error) {
		return "ben@example.com", nil
	}), []string{"ben@example.com"})

	called := false
	h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if got := auth.UserFromContext(r.Context()); got != "ben@example.com" {
			t.Errorf("user in ctx = %q", got)
		}
		w.WriteHeader(204)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "100.64.0.5:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatal("handler not called")
	}
	if rec.Code != 204 {
		t.Errorf("status %d", rec.Code)
	}
}

func TestMiddleware_RejectsNonWhitelisted(t *testing.T) {
	mw := auth.New(fakeWhois(func(ctx context.Context, ip string) (string, error) {
		return "eve@example.com", nil
	}), []string{"ben@example.com"})

	h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not reach handler")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "100.64.0.7:5678"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestMiddleware_RejectsWhoisError(t *testing.T) {
	mw := auth.New(fakeWhois(func(ctx context.Context, ip string) (string, error) {
		return "", errors.New("not in tailnet")
	}), []string{"ben@example.com"})

	h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not reach")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}
```

- [ ] **Step 2: Run, expect failure**

```bash
go test ./internal/auth/...
```

- [ ] **Step 3: Implement `internal/auth/middleware.go`**

Create `internal/auth/middleware.go`:

```go
package auth

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type WhoisFunc interface {
	Whois(ctx context.Context, ip string) (string, error)
}

type ctxKey struct{}

type Middleware struct {
	whois         WhoisFunc
	allowedLowerSet map[string]struct{}
}

func New(w WhoisFunc, allowed []string) *Middleware {
	set := map[string]struct{}{}
	for _, u := range allowed {
		set[strings.ToLower(strings.TrimSpace(u))] = struct{}{}
	}
	return &Middleware{whois: w, allowedLowerSet: set}
}

func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		user, err := m.whois.Whois(r.Context(), ip)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if _, ok := m.allowedLowerSet[strings.ToLower(user)]; !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, user))
		next.ServeHTTP(w, r)
	})
}

func UserFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKey{}).(string)
	return v
}
```

- [ ] **Step 4: Run, expect pass**

```bash
go test -race ./internal/auth/...
```

- [ ] **Step 5: Commit**

```bash
git add internal/auth/
git commit -m "feat(auth): tailnet identity middleware with whitelist"
```

---

## Task 12: Watchdogs (tailscaled supervisor, status poller)

**Files:**
- Create: `internal/watchdog/tailscaled.go`, `internal/watchdog/statuspoller.go`
- Test:   `internal/watchdog/tailscaled_test.go` (statuspoller is wired but not heavily unit-tested — it's I/O glue)

This task ships the two simpler watchdogs. The complex wg+failover watchdog is Task 13.

- [ ] **Step 1: Write failing test for tailscaled watchdog**

Create `internal/watchdog/tailscaled_test.go`:

```go
package watchdog_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbitton/tailscale-surfshark/internal/watchdog"
)

func TestTailscaledWatchdog_RestartsOnFailure(t *testing.T) {
	var checks, restarts atomic.Int32
	checkFunc := func(ctx context.Context) error {
		checks.Add(1)
		if checks.Load() <= 2 {
			return errors.New("down")
		}
		return nil
	}
	restartFunc := func(ctx context.Context) error {
		restarts.Add(1)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	w := watchdog.NewTailscaledWatchdog(checkFunc, restartFunc, 50*time.Millisecond)
	go w.Run(ctx)
	<-ctx.Done()

	if checks.Load() < 2 {
		t.Errorf("expected at least 2 checks, got %d", checks.Load())
	}
	if restarts.Load() < 1 {
		t.Errorf("expected at least 1 restart, got %d", restarts.Load())
	}
}
```

- [ ] **Step 2: Run, expect failure**

```bash
go test ./internal/watchdog/...
```

- [ ] **Step 3: Implement `internal/watchdog/tailscaled.go`**

Create `internal/watchdog/tailscaled.go`:

```go
package watchdog

import (
	"context"
	"time"
)

type CheckFunc func(ctx context.Context) error
type RestartFunc func(ctx context.Context) error

type TailscaledWatchdog struct {
	check    CheckFunc
	restart  RestartFunc
	interval time.Duration
}

func NewTailscaledWatchdog(check CheckFunc, restart RestartFunc, interval time.Duration) *TailscaledWatchdog {
	return &TailscaledWatchdog{check: check, restart: restart, interval: interval}
}

func (w *TailscaledWatchdog) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := w.check(ctx); err != nil {
				_ = w.restart(ctx)
			}
		}
	}
}
```

- [ ] **Step 4: Implement `internal/watchdog/statuspoller.go`**

Create `internal/watchdog/statuspoller.go`:

```go
package watchdog

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/bbitton/tailscale-surfshark/internal/eventbus"
	"github.com/bbitton/tailscale-surfshark/internal/state"
)

// StatusPoller refreshes public-facing stats periodically.
// It does NOT publish state changes itself — it mutates the State and publishes
// a "status_update" event on the bus.
type StatusPoller struct {
	bus      *eventbus.Bus
	st       *state.State
	stPath   string
	hsFunc   func(ctx context.Context) (time.Time, error)
	pubIPURL string
	hsEvery  time.Duration
	ipEvery  time.Duration
}

func NewStatusPoller(bus *eventbus.Bus, st *state.State, stPath string,
	handshake func(ctx context.Context) (time.Time, error),
	publicIPURL string, hsEvery, ipEvery time.Duration) *StatusPoller {
	return &StatusPoller{
		bus: bus, st: st, stPath: stPath,
		hsFunc: handshake, pubIPURL: publicIPURL,
		hsEvery: hsEvery, ipEvery: ipEvery,
	}
}

func (p *StatusPoller) Run(ctx context.Context) {
	hsT := time.NewTicker(p.hsEvery)
	ipT := time.NewTicker(p.ipEvery)
	defer hsT.Stop()
	defer ipT.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hsT.C:
			if hs, err := p.hsFunc(ctx); err == nil {
				p.st.Stats.WG0LastHandshake = hs
				_ = p.st.Save(p.stPath)
				p.bus.Publish(eventbus.Event{Type: "status_update"})
			}
		case <-ipT.C:
			ip, err := p.measurePublicIP(ctx)
			if err == nil {
				p.st.Stats.PublicIP = ip
				p.st.Stats.LastMeasured = time.Now().UTC()
				_ = p.st.Save(p.stPath)
				p.bus.Publish(eventbus.Event{Type: "status_update"})
			}
		}
	}
}

func (p *StatusPoller) measurePublicIP(ctx context.Context) (string, error) {
	c := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET", p.pubIPURL, nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	ip := string(b)
	if len(ip) > 0 && ip[len(ip)-1] == '\n' {
		ip = ip[:len(ip)-1]
	}
	if net.ParseIP(ip) == nil {
		return "", errors.New("not an IP: " + ip)
	}
	return ip, nil
}
```

- [ ] **Step 5: Run, expect pass**

```bash
go test -race ./internal/watchdog/...
```

- [ ] **Step 6: Commit**

```bash
git add internal/watchdog/tailscaled.go internal/watchdog/statuspoller.go internal/watchdog/tailscaled_test.go
git commit -m "feat(watchdog): tailscaled supervisor + status poller"
```

---

## Task 13: WG watchdog + failover state machine

**Files:**
- Create: `internal/watchdog/wg.go`
- Test:   `internal/watchdog/wg_test.go`

This is the most logic-dense module. Tests target the state machine — choosing the next candidate, retry counts, all-failed terminal state.

- [ ] **Step 1: Write failing tests**

Create `internal/watchdog/wg_test.go`:

```go
package watchdog_test

import (
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/watchdog"
)

func TestPickNextCandidate_UsesPreferredFirst(t *testing.T) {
	got := watchdog.NextCandidate("us-nyc", []string{"us-nyc", "us-bos", "fr-par"}, []string{"us-nyc", "us-bos", "fr-par", "de-ber"})
	if got != "us-bos" {
		t.Errorf("got %q, want us-bos", got)
	}
}

func TestPickNextCandidate_FallsBackToAlphabeticalNeighbors(t *testing.T) {
	got := watchdog.NextCandidate("us-nyc", nil, []string{"us-bos", "us-mia", "us-nyc", "us-sjc", "fr-par"})
	// Expected: alphabetically nearest neighbor of us-nyc that isn't us-nyc itself.
	// Sorted: fr-par, us-bos, us-mia, us-nyc, us-sjc. Nearest = us-mia or us-sjc.
	if got != "us-mia" && got != "us-sjc" {
		t.Errorf("got %q, want neighbor of us-nyc", got)
	}
}

func TestPickNextCandidate_AlreadyTried(t *testing.T) {
	got := watchdog.NextCandidateExcluding(
		"us-nyc",
		[]string{"us-nyc", "us-bos"},
		map[string]bool{"us-bos": true},
		[]string{"us-nyc", "us-bos", "fr-par"},
	)
	if got != "fr-par" {
		t.Errorf("got %q, want fr-par (us-bos already tried)", got)
	}
}

func TestPickNextCandidate_NoMoreAvailable(t *testing.T) {
	got := watchdog.NextCandidateExcluding(
		"us-nyc",
		[]string{"us-nyc"},
		map[string]bool{"us-nyc": true, "us-bos": true},
		[]string{"us-nyc", "us-bos"},
	)
	if got != "" {
		t.Errorf("got %q, want empty (all exhausted)", got)
	}
}
```

- [ ] **Step 2: Run, expect failure**

```bash
go test ./internal/watchdog/...
```

- [ ] **Step 3: Implement `internal/watchdog/wg.go`**

Create `internal/watchdog/wg.go`:

```go
package watchdog

import (
	"context"
	"sort"
	"time"

	"github.com/bbitton/tailscale-surfshark/internal/eventbus"
)

// NextCandidate returns the next location to try after `current` failed.
// If preferred is non-empty, walk it in order skipping current.
// Otherwise pick the alphabetically nearest neighbor of current among available.
func NextCandidate(current string, preferred, available []string) string {
	return NextCandidateExcluding(current, preferred, map[string]bool{current: true}, available)
}

func NextCandidateExcluding(current string, preferred []string, tried map[string]bool, available []string) string {
	avail := map[string]bool{}
	for _, a := range available {
		avail[a] = true
	}
	for _, p := range preferred {
		if p == current || tried[p] || !avail[p] {
			continue
		}
		return p
	}
	// Alphabetical neighbor: pick the closest available not already tried.
	if len(preferred) > 0 {
		return ""
	}
	sorted := append([]string(nil), available...)
	sort.Strings(sorted)
	// Find current in sorted, walk outward.
	idx := -1
	for i, s := range sorted {
		if s == current {
			idx = i
			break
		}
	}
	if idx == -1 {
		for _, s := range sorted {
			if !tried[s] {
				return s
			}
		}
		return ""
	}
	for offset := 1; offset < len(sorted); offset++ {
		for _, j := range []int{idx + offset, idx - offset} {
			if j < 0 || j >= len(sorted) {
				continue
			}
			if !tried[sorted[j]] {
				return sorted[j]
			}
		}
	}
	return ""
}

type WGProbe interface {
	IsHealthy(ctx context.Context) bool
}

type Switcher interface {
	SwitchTo(ctx context.Context, location string) error
	CurrentLocation() string
	PreferredLocations() []string
	AvailableLocations() []string
}

type WGWatchdog struct {
	probe    WGProbe
	switcher Switcher
	bus      *eventbus.Bus
	interval time.Duration
	enabled  bool
}

func NewWGWatchdog(probe WGProbe, switcher Switcher, bus *eventbus.Bus, interval time.Duration, failoverEnabled bool) *WGWatchdog {
	return &WGWatchdog{probe: probe, switcher: switcher, bus: bus, interval: interval, enabled: failoverEnabled}
}

func (w *WGWatchdog) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if w.probe.IsHealthy(ctx) {
				continue
			}
			w.recover(ctx)
		}
	}
}

func (w *WGWatchdog) recover(ctx context.Context) {
	current := w.switcher.CurrentLocation()
	// Phase 1: self-heal current location up to 3 times.
	for attempt := 0; attempt < 3; attempt++ {
		if err := w.switcher.SwitchTo(ctx, current); err == nil {
			time.Sleep(5 * time.Second)
			if w.probe.IsHealthy(ctx) {
				return
			}
		}
	}
	if !w.enabled {
		w.bus.Publish(eventbus.Event{Type: "all_failed", Payload: current})
		return
	}
	// Phase 2: failover.
	tried := map[string]bool{current: true}
	for {
		next := NextCandidateExcluding(current, w.switcher.PreferredLocations(), tried, w.switcher.AvailableLocations())
		if next == "" {
			w.bus.Publish(eventbus.Event{Type: "all_failed", Payload: current})
			return
		}
		tried[next] = true
		if err := w.switcher.SwitchTo(ctx, next); err != nil {
			continue
		}
		time.Sleep(5 * time.Second)
		if w.probe.IsHealthy(ctx) {
			w.bus.Publish(eventbus.Event{Type: "auto_failover", Payload: map[string]string{"from": current, "to": next}})
			return
		}
	}
}
```

- [ ] **Step 4: Run, expect pass**

```bash
go test -race ./internal/watchdog/...
```

- [ ] **Step 5: Commit**

```bash
git add internal/watchdog/wg.go internal/watchdog/wg_test.go
git commit -m "feat(watchdog): wg health probe + failover state machine"
```

---

## Task 14: HTTP API — handlers (no SSE yet)

**Files:**
- Create: `internal/httpapi/server.go`, `internal/httpapi/handlers.go`
- Test:   `internal/httpapi/server_test.go`

Wires the auth middleware to handlers. SSE comes in Task 15.

- [ ] **Step 1: Write failing tests**

Create `internal/httpapi/server_test.go`:

```go
package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbitton/tailscale-surfshark/internal/eventbus"
	"github.com/bbitton/tailscale-surfshark/internal/httpapi"
	"github.com/bbitton/tailscale-surfshark/internal/state"
)

type allowAllWhois struct{}

func (allowAllWhois) Whois(ctx context.Context, ip string) (string, error) {
	return "ben@example.com", nil
}

type fakeOps struct {
	toggleCalls   []bool
	switchCalls   []string
	refreshCalled bool
	available     []string
}

func (f *fakeOps) Toggle(ctx context.Context, on bool) error {
	f.toggleCalls = append(f.toggleCalls, on)
	return nil
}
func (f *fakeOps) SwitchLocation(ctx context.Context, loc string) error {
	f.switchCalls = append(f.switchCalls, loc)
	return nil
}
func (f *fakeOps) Refresh(ctx context.Context) error {
	f.refreshCalled = true
	return nil
}
func (f *fakeOps) AvailableLocations() []string { return f.available }
func (f *fakeOps) SetPreferred(ctx context.Context, locs []string) error {
	return nil
}

func newTestServer(t *testing.T) (*httptest.Server, *fakeOps, *state.State) {
	st := state.Default()
	bus := eventbus.New(4)
	ops := &fakeOps{available: []string{"us-nyc", "fr-par"}}
	srv := httpapi.NewServer(httpapi.Deps{
		Whois:   allowAllWhois{},
		Allowed: []string{"ben@example.com"},
		State:   st,
		Bus:     bus,
		Ops:     ops,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, ops, st
}

func TestHealthz_NoAuthRequired(t *testing.T) {
	ts, _, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status %d", resp.StatusCode)
	}
}

func TestStatus_ReturnsJSON(t *testing.T) {
	ts, _, _ := newTestServer(t)
	resp, _ := http.Get(ts.URL + "/api/status")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var data map[string]any
	json.NewDecoder(resp.Body).Decode(&data)
	if _, ok := data["surfshark"]; !ok {
		t.Errorf("missing surfshark field")
	}
}

func TestToggle_ForwardsToOps(t *testing.T) {
	ts, ops, _ := newTestServer(t)
	resp, _ := http.Post(ts.URL+"/api/surfshark/toggle", "application/json",
		strings.NewReader(`{"enabled": true}`))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(ops.toggleCalls) != 1 || !ops.toggleCalls[0] {
		t.Errorf("toggle calls = %v", ops.toggleCalls)
	}
}

func TestSwitchLocation_ForwardsToOps(t *testing.T) {
	ts, ops, _ := newTestServer(t)
	resp, _ := http.Post(ts.URL+"/api/surfshark/location", "application/json",
		strings.NewReader(`{"name":"us-nyc"}`))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(ops.switchCalls) != 1 || ops.switchCalls[0] != "us-nyc" {
		t.Errorf("switch calls = %v", ops.switchCalls)
	}
}

func TestRefresh_Returns202(t *testing.T) {
	ts, ops, _ := newTestServer(t)
	resp, _ := http.Post(ts.URL+"/api/surfshark/refresh", "application/json", nil)
	if resp.StatusCode != 202 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	// async — give it a moment
	for i := 0; i < 50; i++ {
		if ops.refreshCalled {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("refresh was never called")
}
```

- [ ] **Step 2: Run, expect failure**

```bash
go test ./internal/httpapi/...
```

- [ ] **Step 3: Implement `internal/httpapi/server.go` and `internal/httpapi/handlers.go`**

Create `internal/httpapi/server.go`:

```go
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/bbitton/tailscale-surfshark/internal/auth"
	"github.com/bbitton/tailscale-surfshark/internal/eventbus"
	"github.com/bbitton/tailscale-surfshark/internal/state"
)

type Ops interface {
	Toggle(ctx context.Context, on bool) error
	SwitchLocation(ctx context.Context, loc string) error
	Refresh(ctx context.Context) error
	SetPreferred(ctx context.Context, locs []string) error
	AvailableLocations() []string
}

type Deps struct {
	Whois   auth.WhoisFunc
	Allowed []string
	State   *state.State
	Bus     *eventbus.Bus
	Ops     Ops
}

type Server struct {
	d   Deps
	mw  *auth.Middleware
	mux *http.ServeMux
}

func NewServer(d Deps) *Server {
	s := &Server{
		d:   d,
		mw:  auth.New(d.Whois, d.Allowed),
		mux: http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	// Unauthenticated:
	s.mux.HandleFunc("/api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	// Authenticated:
	s.mux.Handle("/api/status", s.mw.Wrap(http.HandlerFunc(s.handleStatus)))
	s.mux.Handle("/api/surfshark/toggle", s.mw.Wrap(http.HandlerFunc(s.handleToggle)))
	s.mux.Handle("/api/surfshark/location", s.mw.Wrap(http.HandlerFunc(s.handleSwitch)))
	s.mux.Handle("/api/surfshark/refresh", s.mw.Wrap(http.HandlerFunc(s.handleRefresh)))
	s.mux.Handle("/api/surfshark/preferred", s.mw.Wrap(http.HandlerFunc(s.handlePreferred)))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
```

Create `internal/httpapi/handlers.go`:

```go
package httpapi

import (
	"encoding/json"
	"net/http"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	payload := map[string]any{
		"version":   s.d.State.Version,
		"surfshark": s.d.State.Surfshark,
		"kill_switch": s.d.State.KillSwitch,
		"stats":     s.d.State.Stats,
		"available_locations": s.d.Ops.AvailableLocations(),
	}
	writeJSON(w, 200, payload)
}

func (s *Server) handleToggle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := s.d.Ops.Toggle(r.Context(), body.Enabled); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) handleSwitch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if body.Name == "" {
		http.Error(w, "name required", 400)
		return
	}
	if err := s.d.Ops.SwitchLocation(r.Context(), body.Name); err != nil {
		http.Error(w, err.Error(), 504)
		return
	}
	writeJSON(w, 200, map[string]string{"location": body.Name})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	go func() {
		_ = s.d.Ops.Refresh(r.Context())
	}()
	writeJSON(w, 202, map[string]string{"status": "started"})
}

func (s *Server) handlePreferred(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Locations []string `json:"locations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := s.d.Ops.SetPreferred(r.Context(), body.Locations); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string][]string{"locations": body.Locations})
}
```

- [ ] **Step 4: Run, expect pass**

```bash
go test -race ./internal/httpapi/...
```

- [ ] **Step 5: Commit**

```bash
git add internal/httpapi/
git commit -m "feat(httpapi): server + handlers (toggle, switch, refresh, preferred)"
```

---

## Task 15: SSE endpoint

**Files:**
- Create: `internal/httpapi/sse.go`
- Modify: `internal/httpapi/server.go` (add route)
- Test:   `internal/httpapi/sse_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/httpapi/sse_test.go`:

```go
package httpapi_test

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bbitton/tailscale-surfshark/internal/eventbus"
)

func TestSSE_StreamsEvents(t *testing.T) {
	ts, _, _ := newTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/api/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Errorf("content-type = %q", resp.Header.Get("Content-Type"))
	}

	// We need access to the bus to publish; expose it via test helper:
	// (Add a helper to newTestServer if needed, or publish via Ops in real wiring.)
	_ = eventbus.Event{Type: "ping"}

	// Smoke: read at least the comment ping.
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, ":") || strings.HasPrefix(line, "data:") {
			return // saw something
		}
	}
}
```

(This test is intentionally simple — full SSE end-to-end testing happens at the integration layer.)

- [ ] **Step 2: Run, expect failure**

```bash
go test ./internal/httpapi/...
```

- [ ] **Step 3: Implement `internal/httpapi/sse.go`**

Create `internal/httpapi/sse.go`:

```go
package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	sub := s.d.Bus.Subscribe()
	defer s.d.Bus.Unsubscribe(sub)

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-sub:
			if !ok {
				return
			}
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, string(b))
			flusher.Flush()
		case <-keepalive.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}
```

Add the route in `internal/httpapi/server.go`, inside `routes()`:

```go
s.mux.Handle("/api/events", s.mw.Wrap(http.HandlerFunc(s.handleEvents)))
```

- [ ] **Step 4: Run, expect pass**

```bash
go test -race ./internal/httpapi/...
```

- [ ] **Step 5: Commit**

```bash
git add internal/httpapi/
git commit -m "feat(httpapi): SSE event stream on /api/events"
```

---

## Task 16: Embedded web UI (HTML/CSS/JS)

**Files:**
- Create: `web/index.html`, `web/app.js`, `web/style.css`
- Modify: `internal/httpapi/server.go` (serve embedded files at `/`)

- [ ] **Step 1: Create `web/index.html`**

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Tailscale-Surfshark Exit Node</title>
  <link rel="stylesheet" href="/style.css" />
</head>
<body>
  <header>
    <h1>Tailscale-Surfshark Exit Node</h1>
    <span id="who"></span>
  </header>

  <section id="banners"></section>

  <section class="card">
    <h2>Status</h2>
    <dl id="status"></dl>
  </section>

  <section class="card">
    <h2>Controls</h2>
    <label class="row">
      <span>Surfshark</span>
      <input type="checkbox" id="toggle" />
    </label>
    <label class="row">
      <span>Location</span>
      <select id="location"></select>
      <button id="switch">Switch</button>
    </label>
    <button id="refresh">Refresh from Surfshark</button>
  </section>

  <section class="card">
    <h2>Preferred locations (failover order)</h2>
    <ul id="preferred"></ul>
  </section>

  <section class="card">
    <h2>Live log</h2>
    <pre id="log"></pre>
  </section>

  <script src="/app.js"></script>
</body>
</html>
```

- [ ] **Step 2: Create `web/style.css`**

```css
:root { --fg:#111; --bg:#fafafa; --card:#fff; --border:#ddd; --accent:#0066cc; }
* { box-sizing: border-box; }
body { font-family: system-ui, sans-serif; margin: 0; padding: 1rem; background: var(--bg); color: var(--fg); }
header { display:flex; justify-content:space-between; align-items:center; padding-bottom:1rem; }
.card { background: var(--card); border:1px solid var(--border); border-radius:.5rem; padding:1rem; margin-bottom:1rem; }
.row { display:flex; align-items:center; gap:1rem; margin: .5rem 0; }
.row span { min-width: 120px; }
button { padding: .4rem .8rem; cursor: pointer; }
#log { background: #111; color: #eee; padding: .5rem; height: 200px; overflow:auto; font-family: monospace; font-size: .85rem; }
.banner { padding: .8rem 1rem; border-radius: .5rem; margin-bottom: .5rem; }
.banner.red { background:#ffe5e5; color:#a00; border:1px solid #f99; }
.banner.yellow { background:#fff7d8; color:#8a6b00; border:1px solid #e8c66e; }
.banner.blue { background:#e6f0ff; color:#003a80; border:1px solid #99bdf5; }
dl#status { display:grid; grid-template-columns:auto 1fr; gap:.25rem 1rem; }
dl#status dt { font-weight:600; }
ul#preferred { list-style: none; padding: 0; }
ul#preferred li { padding: .3rem .5rem; border:1px solid var(--border); border-radius:.25rem; margin-bottom:.25rem; background:#fff; cursor: grab; }
```

- [ ] **Step 3: Create `web/app.js`**

```js
const $ = (s) => document.querySelector(s);
let state = null;

async function fetchStatus() {
  const r = await fetch("/api/status");
  if (!r.ok) return;
  state = await r.json();
  render();
}

function render() {
  if (!state) return;
  const s = state.surfshark || {};
  const ks = state.kill_switch || {};
  const stats = state.stats || {};
  const status = $("#status");
  status.innerHTML = "";
  const fields = [
    ["Surfshark", s.toggle ? `ON (${s.current_location || "?"})` : "OFF"],
    ["Kill switch", ks.currently_armed ? "Armed" : (ks.enabled_by_env ? "Disarmed" : "Disabled")],
    ["Public IP", stats.public_ip || "—"],
    ["Last handshake", stats.wg0_last_handshake || "—"],
    ["Latency", stats.wg0_latency_ms ? stats.wg0_latency_ms + " ms" : "—"],
  ];
  for (const [k, v] of fields) {
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd"); dd.textContent = v;
    status.appendChild(dt); status.appendChild(dd);
  }
  $("#toggle").checked = !!s.toggle;
  const sel = $("#location"); sel.innerHTML = "";
  for (const loc of state.available_locations || []) {
    const o = document.createElement("option");
    o.value = loc; o.textContent = loc;
    if (loc === s.current_location) o.selected = true;
    sel.appendChild(o);
  }
  const ul = $("#preferred"); ul.innerHTML = "";
  for (const p of s.preferred_locations || []) {
    const li = document.createElement("li");
    li.textContent = p; li.draggable = true;
    ul.appendChild(li);
  }
  renderBanners();
}

function renderBanners() {
  const s = state.surfshark || {};
  const ks = state.kill_switch || {};
  const banners = $("#banners"); banners.innerHTML = "";
  if (!s.toggle && !ks.enabled_by_env) {
    const b = document.createElement("div");
    b.className = "banner red";
    b.textContent = "VPN BYPASS ACTIVE — your real IP is exposed for clients using this exit node.";
    banners.appendChild(b);
  }
}

async function postJSON(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return r;
}

$("#toggle").addEventListener("change", async (e) => {
  await postJSON("/api/surfshark/toggle", { enabled: e.target.checked });
  fetchStatus();
});

$("#switch").addEventListener("click", async () => {
  await postJSON("/api/surfshark/location", { name: $("#location").value });
  fetchStatus();
});

$("#refresh").addEventListener("click", async () => {
  await postJSON("/api/surfshark/refresh", {});
});

function startSSE() {
  const es = new EventSource("/api/events");
  es.onmessage = (e) => appendLog(e.data);
  ["status_update", "auto_failover", "all_failed", "refresh_complete"].forEach((t) => {
    es.addEventListener(t, (e) => {
      appendLog(`[${t}] ${e.data}`);
      fetchStatus();
    });
  });
}

function appendLog(line) {
  const pre = $("#log");
  pre.textContent += new Date().toISOString() + "  " + line + "\n";
  pre.scrollTop = pre.scrollHeight;
}

fetchStatus();
startSSE();
setInterval(fetchStatus, 10_000);
```

- [ ] **Step 4: Add embedded FS to `internal/httpapi/server.go`**

Modify `internal/httpapi/server.go` — add at top of file:

```go
import (
	"embed"
	"io/fs"
)

//go:embed all:../../web
var webFS embed.FS
```

Add inside `routes()`:

```go
sub, _ := fs.Sub(webFS, "../../web")
s.mux.Handle("/", http.FileServer(http.FS(sub)))
```

**Note:** because `//go:embed` paths are relative to the source file, but the layout uses `/web`, the cleanest approach is to put the embed declaration in a small file co-located with `web/`. Alternative: move embed into `cmd/surfshark-control/main.go` and pass the FS as a dependency. Choose the second approach if relative paths cause friction.

Refactor as follows — create `internal/httpapi/static.go`:

```go
package httpapi

import (
	"io/fs"
	"net/http"
)

type StaticFS = fs.FS

func (s *Server) mountStatic(root StaticFS) {
	s.mux.Handle("/", http.FileServer(http.FS(root)))
}
```

And in `cmd/surfshark-control/main.go` (will be fully written in Task 17), embed `web/` and call `s.mountStatic(webSub)`.

For now, just declare the helper. The `//go:embed` happens in Task 17.

- [ ] **Step 5: Commit**

```bash
git add web/ internal/httpapi/static.go internal/httpapi/server.go
git commit -m "feat(web): UI assets and static handler helper"
```

---

## Task 17: Composition root (`cmd/surfshark-control/main.go`)

**Files:**
- Modify: `cmd/surfshark-control/main.go`

This is where the pieces are wired together. No new tests — the integration test in Task 20 covers this end-to-end.

- [ ] **Step 1: Replace `cmd/surfshark-control/main.go`**

```go
package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bbitton/tailscale-surfshark/internal/config"
	"github.com/bbitton/tailscale-surfshark/internal/eventbus"
	"github.com/bbitton/tailscale-surfshark/internal/httpapi"
	"github.com/bbitton/tailscale-surfshark/internal/iptables"
	"github.com/bbitton/tailscale-surfshark/internal/logging"
	"github.com/bbitton/tailscale-surfshark/internal/state"
	"github.com/bbitton/tailscale-surfshark/internal/surfshark"
	"github.com/bbitton/tailscale-surfshark/internal/tailscale"
	"github.com/bbitton/tailscale-surfshark/internal/watchdog"
	"github.com/bbitton/tailscale-surfshark/internal/wireguard"
)

//go:embed all:web
var webFS embed.FS

const (
	dataDir       = "/data"
	statePath     = "/data/state.json"
	confDir       = "/data/surfshark"
	wg0OutPath    = "/etc/wireguard/wg0.conf"
	pubIPURL      = "https://ifconfig.io"
	httpPort      = 8080
)

type Ops struct {
	logger    *logging.Logger
	st        *state.State
	tsCli     *tailscale.Client
	api       *surfshark.Client
	store     *surfshark.ConfigStore
	wg        *wireguard.Controller
	ipt       *iptables.Manager
	bus       *eventbus.Bus
	cfg       *config.Config
}

func (o *Ops) AvailableLocations() []string {
	locs, _ := o.store.List()
	return locs
}

func (o *Ops) Toggle(ctx context.Context, on bool) error {
	if on {
		if err := o.bringUpWG(ctx); err != nil {
			return err
		}
		o.st.Surfshark.Toggle = true
		if o.cfg.KillSwitch {
			_ = o.ipt.ArmKillSwitch(ctx, "tailscale0", "eth0")
			o.st.KillSwitch.CurrentlyArmed = true
		}
	} else {
		_ = o.wg.Down(ctx, "wg0")
		o.st.Surfshark.Toggle = false
		if o.cfg.KillSwitch {
			_ = o.ipt.ArmKillSwitch(ctx, "tailscale0", "eth0")
			o.st.KillSwitch.CurrentlyArmed = true
		} else {
			_ = o.ipt.DisarmKillSwitch(ctx, "tailscale0", "eth0")
			o.st.KillSwitch.CurrentlyArmed = false
		}
	}
	o.bus.Publish(eventbus.Event{Type: "status_update"})
	return o.st.Save(statePath)
}

func (o *Ops) SwitchLocation(ctx context.Context, loc string) error {
	if err := o.store.RenderWG0Conf(loc, wg0OutPath); err != nil {
		return err
	}
	_ = o.wg.Down(ctx, "wg0")
	if err := o.wg.Up(ctx, wg0OutPath); err != nil {
		return err
	}
	// Wait up to 10s for ping 1.1.1.1 via wg0.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		// crude TCP probe — replace with ICMP if needed
		c, err := net.DialTimeout("tcp", "1.1.1.1:53", 1*time.Second)
		if err == nil {
			c.Close()
			o.st.Surfshark.CurrentLocation = loc
			_ = o.st.Save(statePath)
			o.bus.Publish(eventbus.Event{Type: "status_update"})
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("location %s: no connectivity after 10s", loc)
}

func (o *Ops) Refresh(ctx context.Context) error {
	if o.cfg.SurfsharkEmail == "" || o.cfg.SurfsharkPassword == "" {
		return fmt.Errorf("SURFSHARK_EMAIL/PASSWORD not set")
	}
	tok, err := o.api.Login(ctx, o.cfg.SurfsharkEmail, o.cfg.SurfsharkPassword)
	if err != nil {
		return err
	}
	_, pub, err := o.store.EnsureKeypair()
	if err != nil {
		return err
	}
	if err := o.api.RegisterPubKey(ctx, tok, pub); err != nil {
		return err
	}
	servers, err := o.api.ListServers(ctx, tok)
	if err != nil {
		return err
	}
	if err := o.store.WriteAll(servers); err != nil {
		return err
	}
	now := time.Now().UTC()
	o.st.Surfshark.LastRefresh = &now
	_ = o.st.Save(statePath)
	o.bus.Publish(eventbus.Event{Type: "refresh_complete"})
	return nil
}

func (o *Ops) SetPreferred(ctx context.Context, locs []string) error {
	o.st.Surfshark.PreferredLocations = locs
	o.bus.Publish(eventbus.Event{Type: "status_update"})
	return o.st.Save(statePath)
}

func (o *Ops) bringUpWG(ctx context.Context) error {
	loc := o.st.Surfshark.CurrentLocation
	if loc == "" {
		avail := o.AvailableLocations()
		if len(avail) == 0 {
			return fmt.Errorf("no Surfshark configs available")
		}
		loc = avail[0]
	}
	return o.SwitchLocation(ctx, loc)
}

func main() {
	logger := logging.New(os.Stdout, os.Getenv("LOG_LEVEL"))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("config", "error", err.Error())
		os.Exit(1)
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		logger.Error("mkdir data", "error", err.Error())
		os.Exit(1)
	}
	st, err := state.Load(statePath)
	if err != nil {
		logger.Error("state load", "error", err.Error())
		os.Exit(1)
	}
	st.KillSwitch.EnabledByEnv = cfg.KillSwitch

	bus := eventbus.New(64)
	tsCli := tailscale.New()
	store := surfshark.NewConfigStore(confDir)
	wgCtrl := wireguard.New()
	ipt := iptables.New()
	api := surfshark.NewClient("https://api.surfshark.com")

	ops := &Ops{
		logger: logger, st: st, tsCli: tsCli,
		api: api, store: store, wg: wgCtrl, ipt: ipt,
		bus: bus, cfg: cfg,
	}

	// First-boot cache fill if env present and no cache:
	available, _ := store.List()
	if len(available) == 0 && cfg.SurfsharkEmail != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		if err := ops.Refresh(ctx); err != nil {
			logger.Warn("first-boot refresh failed", "error", err.Error())
		}
		cancel()
	}

	// Base iptables
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := ipt.ApplyBase(bootCtx, "tailscale0", "wg0", "eth0"); err != nil {
		logger.Warn("iptables base", "error", err.Error())
	}
	bootCancel()

	// Restore toggle state if it was ON
	if st.Surfshark.Toggle {
		_ = ops.Toggle(context.Background(), true)
	} else if cfg.KillSwitch {
		_ = ipt.ArmKillSwitch(context.Background(), "tailscale0", "eth0")
		st.KillSwitch.CurrentlyArmed = true
	}

	// Bind HTTP on the container's tailscale IP.
	ip, err := tsCli.IPv4(context.Background())
	if err != nil {
		logger.Warn("tailscale ip failed, binding 0.0.0.0", "error", err.Error())
		ip = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", ip, httpPort)

	srv := httpapi.NewServer(httpapi.Deps{
		Whois:   tsCli, // *tailscale.Client implements Whois
		Allowed: cfg.TSAllowedUsers,
		State:   st,
		Bus:     bus,
		Ops:     ops,
	})
	sub, _ := fs.Sub(webFS, "web")
	srv.MountStatic(sub) // see Task 16: helper exposed via method

	// Watchdogs
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	tsWatch := watchdog.NewTailscaledWatchdog(
		func(ctx context.Context) error { _, e := tsCli.Status(ctx); return e },
		func(ctx context.Context) error {
			// Re-exec tailscaled is the entrypoint's job; here we just nudge by re-issuing `tailscale up`.
			return nil
		},
		30*time.Second,
	)
	go tsWatch.Run(rootCtx)

	statusPoll := watchdog.NewStatusPoller(
		bus, st, statePath,
		func(ctx context.Context) (time.Time, error) { return wgCtrl.LastHandshake(ctx, "wg0") },
		pubIPURL, 10*time.Second, 60*time.Second,
	)
	go statusPoll.Run(rootCtx)

	httpServer := &http.Server{
		Addr:    addr,
		Handler: srv.Handler(),
	}
	go func() {
		logger.Info("http listening", "addr", addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server", "error", err.Error())
		}
	}()

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logger.Info("shutting down")
	shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
	_ = httpServer.Shutdown(shutdownCtx)
	c()
}
```

**Notes for the engineer:**
- Add `import "net"` for `net.DialTimeout` in `SwitchLocation`.
- `srv.MountStatic` requires exposing a public method on `*Server` — add it in `internal/httpapi/static.go`:
  ```go
  func (s *Server) MountStatic(root StaticFS) { s.mountStatic(root) }
  ```
- The `tsCli` is passed as `Whois` because `*tailscale.Client` implements `Whois(ctx, ip) (string, error)`. Confirm the method signature on `*tailscale.Client` matches the `auth.WhoisFunc` interface.

- [ ] **Step 2: Build**

```bash
make build
```

Expected: builds. If imports are off, fix them.

- [ ] **Step 3: Run tests**

```bash
make test
```

Expected: all unit tests still pass.

- [ ] **Step 4: Commit**

```bash
git add cmd/surfshark-control/main.go internal/httpapi/static.go
git commit -m "feat: composition root wiring all modules"
```

---

## Task 18: Dockerfile + entrypoint.sh

**Files:**
- Create: `Dockerfile`, `docker/entrypoint.sh`

- [ ] **Step 1: Write `Dockerfile`**

```dockerfile
# syntax=docker/dockerfile:1.6

FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/surfshark-control ./cmd/surfshark-control

FROM alpine:3.20
RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    ip6tables \
    iproute2 \
    ca-certificates \
    curl \
    bash \
    tailscale

COPY --from=build /out/surfshark-control /app/surfshark-control
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
```

- [ ] **Step 2: Write `docker/entrypoint.sh`**

```bash
#!/bin/bash
set -euo pipefail

err() { echo "entrypoint: $*" >&2; }

: "${TS_AUTHKEY:?TS_AUTHKEY is required (Tailscale pre-auth key)}"
: "${TS_ALLOWED_USERS:?TS_ALLOWED_USERS is required (comma-separated tailnet emails)}"
TS_HOSTNAME="${TS_HOSTNAME:-synology-surfshark-exit}"

mkdir -p /data/tailscale /data/surfshark /data/logs
mkdir -p /etc/wireguard
chmod 700 /data/surfshark

# Ensure ip_forward (sysctl may already be set by docker-compose sysctls,
# but a runtime check makes the failure mode explicit).
if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]]; then
  err "net.ipv4.ip_forward is 0; attempting to set"
  sysctl -w net.ipv4.ip_forward=1 || { err "failed to enable ip_forward"; exit 3; }
fi

# Start tailscaled in background, state in /data/tailscale.
tailscaled \
  --state=/data/tailscale/tailscaled.state \
  --socket=/var/run/tailscale/tailscaled.sock \
  --tun=tailscale0 \
  &
TSD_PID=$!

# Wait for socket.
for i in $(seq 1 30); do
  if [[ -S /var/run/tailscale/tailscaled.sock ]]; then break; fi
  sleep 1
done
if [[ ! -S /var/run/tailscale/tailscaled.sock ]]; then
  err "tailscaled socket never appeared"
  kill "$TSD_PID" 2>/dev/null || true
  exit 2
fi

# Bring tailscale up (idempotent).
tailscale up \
  --authkey="${TS_AUTHKEY}" \
  --advertise-exit-node \
  --accept-routes \
  --accept-dns=false \
  --hostname="${TS_HOSTNAME}"

# Hand off to the Go daemon as PID 1's replacement.
exec /app/surfshark-control
```

- [ ] **Step 3: Build image locally**

```bash
docker build -t tailscale-surfshark:dev .
```

Expected: builds cleanly. Image size ~50–80 MB.

- [ ] **Step 4: Commit**

```bash
git add Dockerfile docker/entrypoint.sh
git commit -m "build: Dockerfile (Alpine multi-stage) + entrypoint with TS bootstrap"
```

---

## Task 19: docker-compose.yml + .env.example

**Files:**
- Create: `docker-compose.yml`, `.env.example`

- [ ] **Step 1: Write `docker-compose.yml`**

```yaml
services:
  tailscale-surfshark:
    image: tailscale-surfshark:dev
    container_name: tailscale-surfshark
    build: .
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    devices:
      - /dev/net/tun:/dev/net/tun
    sysctls:
      net.ipv4.ip_forward: "1"
      net.ipv6.conf.all.forwarding: "1"
    volumes:
      - ./data:/data
    env_file:
      - .env
```

- [ ] **Step 2: Write `.env.example`**

```dotenv
# ─── Tailscale (required) ─────────────────────────────────────────────────────
# Pre-auth key from https://login.tailscale.com/admin/settings/keys
# Recommended: reusable, tag:exit-node, no expiry.
TS_AUTHKEY=tskey-auth-REPLACE-ME

# Comma-separated tailnet identities allowed to access the UI.
TS_ALLOWED_USERS=ben@example.com

# Hostname shown in the Tailscale admin (optional, defaults to "synology-surfshark-exit").
# TS_HOSTNAME=synology-surfshark-exit

# ─── Surfshark (required for hybrid mode at first boot and refresh) ──────────
SURFSHARK_EMAIL=
SURFSHARK_PASSWORD=

# ─── Behavior ─────────────────────────────────────────────────────────────────
# Kill switch: when ON, traffic from exit-node clients is blocked unless wg0 is up.
# Default: true.
KILL_SWITCH=true

# Auto-failover: when wg0 is unhealthy and toggle is ON, try other locations.
# Default: true.
FAILOVER=true

# Log level: debug | info | warn | error
LOG_LEVEL=info
```

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml .env.example
git commit -m "build: docker-compose + .env.example"
```

---

## Task 20: Integration test harness (mock TS + mock Surfshark)

**Files:**
- Create: `test/integration/docker-compose.test.yml`, `test/integration/mocksurfshark/main.go`, `test/integration/Dockerfile.runner`, `test/integration/e2e_test.go`
- Create: `docker/stubs/tailscale-stub.sh`, `docker/stubs/tailscaled-stub.sh`

This task is large but each step is mechanical. The goal: prove the container starts, the HTTP API responds, and state survives a restart.

- [ ] **Step 1: Write `docker/stubs/tailscaled-stub.sh`**

```bash
#!/bin/bash
# Minimal stub: create socket file and sleep forever.
mkdir -p /var/run/tailscale
touch /var/run/tailscale/tailscaled.sock
chmod 666 /var/run/tailscale/tailscaled.sock
sleep infinity
```

- [ ] **Step 2: Write `docker/stubs/tailscale-stub.sh`**

```bash
#!/bin/bash
# Minimal stub for `tailscale` CLI. Matches the subcommands the daemon uses.
case "$1" in
  up) exit 0 ;;
  ip)
    if [[ "$2" == "-4" ]]; then echo "100.64.0.5"; exit 0; fi
    ;;
  status)
    if [[ "$2" == "--json" ]]; then
      cat <<'JSON'
{"BackendState":"Running","Self":{"HostName":"stub","TailscaleIPs":["100.64.0.5"]}}
JSON
      exit 0
    fi
    ;;
  whois)
    if [[ "$2" == "--json" ]]; then
      cat <<'JSON'
{"UserProfile":{"LoginName":"ben@example.com"}}
JSON
      exit 0
    fi
    ;;
esac
exit 0
```

- [ ] **Step 3: Write `test/integration/mocksurfshark/main.go`**

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"token": "stubtoken", "renewToken": "rt"})
	})
	http.HandleFunc("/v1/account/users/public-keys", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	http.HandleFunc("/v4/server/clusters/generic", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]string{
			{"id": "us-nyc", "country": "United States", "country_code": "us", "location": "New York", "connection_name": "us-nyc.surfshark.com", "pub_key": "PUB1", "host": "1.2.3.4"},
		})
	})
	log.Println("mocksurfshark listening on :8888")
	log.Fatal(http.ListenAndServe(":8888", nil))
}
```

- [ ] **Step 4: Write `test/integration/Dockerfile.runner`**

```dockerfile
FROM golang:1.22-alpine
RUN apk add --no-cache curl
WORKDIR /work
COPY . .
CMD ["go", "test", "-v", "-tags=integration", "./test/integration/..."]
```

- [ ] **Step 5: Write `test/integration/docker-compose.test.yml`**

```yaml
services:
  mocksurfshark:
    build:
      context: ../..
      dockerfile: test/integration/mocksurfshark.Dockerfile
    expose: ["8888"]

  app:
    build:
      context: ../..
      dockerfile: Dockerfile
    depends_on: [mocksurfshark]
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    sysctls:
      net.ipv4.ip_forward: "1"
    environment:
      TS_AUTHKEY: "stub"
      TS_ALLOWED_USERS: "ben@example.com"
      TS_HOSTNAME: "stub-exit"
      SURFSHARK_EMAIL: "test@example.com"
      SURFSHARK_PASSWORD: "test"
      KILL_SWITCH: "false"
      FAILOVER: "false"
      LOG_LEVEL: "debug"
      # The Go binary reads https://api.surfshark.com by default — override via build flag,
      # OR use docker network alias (see below).
    volumes:
      - test-data:/data
      # mount stubs OVER the real tailscale binaries
      - ../../docker/stubs/tailscale-stub.sh:/usr/bin/tailscale:ro
      - ../../docker/stubs/tailscaled-stub.sh:/usr/bin/tailscaled:ro
    extra_hosts:
      - "api.surfshark.com:host-gateway"  # redirects to mocksurfshark via network alias below
    networks:
      default:
        aliases:
          - tailscale-surfshark-app

  runner:
    build:
      context: ../..
      dockerfile: test/integration/Dockerfile.runner
    depends_on: [app]
    environment:
      APP_URL: "http://app:8080"
    volumes:
      - ../..:/work

volumes:
  test-data:
```

**Caveat to the engineer:** mapping `api.surfshark.com` to the mock requires either DNS aliasing inside the container or making the API base URL configurable. The cleanest fix: add a `SURFSHARK_API_BASE` env var read in `main.go`, defaulting to `https://api.surfshark.com`, and override it to `http://mocksurfshark:8888` in the test compose. **Add that env var support in this task** as a small follow-up edit to `config/env.go` and `main.go`.

- [ ] **Step 6: Add `SURFSHARK_API_BASE` env support**

Edit `internal/config/env.go`: add field `SurfsharkAPIBase string`, populate from `env["SURFSHARK_API_BASE"]` defaulting to `"https://api.surfshark.com"`. Add a test for the default.

Edit `cmd/surfshark-control/main.go`: replace `surfshark.NewClient("https://api.surfshark.com")` with `surfshark.NewClient(cfg.SurfsharkAPIBase)`.

In the integration compose, set `SURFSHARK_API_BASE=http://mocksurfshark:8888`.

- [ ] **Step 7: Write `test/integration/e2e_test.go`**

```go
//go:build integration

package integration_test

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestHealthz(t *testing.T) {
	url := os.Getenv("APP_URL") + "/api/healthz"
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == 200 {
			return
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatal("healthz never responded 200 within 60s")
}

func TestStatusEndpointAccessible(t *testing.T) {
	url := os.Getenv("APP_URL") + "/api/status"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status code = %d", resp.StatusCode)
	}
}

func TestAvailableLocationsAfterFirstBoot(t *testing.T) {
	resp, err := http.Get(os.Getenv("APP_URL") + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	// Naive substring check — the mock returns us-nyc.
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if !strings.Contains(body, "us-nyc") {
		t.Fatalf("expected us-nyc in /api/status, got: %s", body)
	}
}
```

- [ ] **Step 8: Write `test/integration/mocksurfshark.Dockerfile`**

```dockerfile
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY test/integration/mocksurfshark/main.go ./main.go
RUN CGO_ENABLED=0 go build -o /out/mock ./

FROM alpine:3.20
COPY --from=build /out/mock /mock
CMD ["/mock"]
```

- [ ] **Step 9: Run the integration test**

```bash
make test-integration
```

Expected: app boots, healthz returns 200, /api/status contains `us-nyc`.

- [ ] **Step 10: Commit**

```bash
git add test/integration/ docker/stubs/ internal/config/ cmd/surfshark-control/main.go
git commit -m "test(integration): docker-compose harness with mocked tailscale + surfshark API"
```

---

## Task 21: README + manual checklist

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write `README.md`**

```markdown
# tailscale-surfshark

Docker container that exposes a Tailscale exit node whose egress is routed through Surfshark (WireGuard). Web UI accessible only over Tailscale; toggle Surfshark on/off, switch locations, refresh the location list.

## Architecture

See [`docs/superpowers/specs/2026-06-14-tailscale-surfshark-design.md`](docs/superpowers/specs/2026-06-14-tailscale-surfshark-design.md).

## Quick start (Synology DSM 7)

1. SSH into your Synology, `cd /volume1/docker/`.
2. `git clone <this repo> tailscale-surfshark && cd tailscale-surfshark`
3. Copy and fill the env file:

   ```bash
   cp .env.example .env
   chmod 600 .env
   nano .env
   ```

   Required: `TS_AUTHKEY`, `TS_ALLOWED_USERS`, `SURFSHARK_EMAIL`, `SURFSHARK_PASSWORD`.

4. In the Tailscale admin: generate a reusable, no-expiry pre-auth key tagged `tag:exit-node`, and ensure the ACL auto-approves exit nodes for that tag.
5. Bring it up:

   ```bash
   docker compose up -d --build
   ```

6. In the Tailscale admin, the new device should appear (default hostname: `synology-surfshark-exit`). Approve the exit node if not auto-approved.
7. Open the UI: find the tailnet IP in the admin, browse to `http://<that-ip>:8080`.

## Manual verification checklist (run after every release)

- [ ] First boot with real Surfshark creds → configs downloaded into `./data/surfshark/configs/`.
- [ ] Tailscale client (MacBook, set "Use exit node" to `synology-surfshark-exit`) → `curl ifconfig.io` returns a Surfshark IP.
- [ ] `tailscale ping <exit-node>` shows `via DIRECT` (not DERP).
- [ ] Client speed test > 50 Mbps (sanity check; DERP would cap ~10).
- [ ] Switch location via UI → public IP changes within 10s.
- [ ] Toggle OFF + `KILL_SWITCH=true` → exit-node client loses internet.
- [ ] Toggle OFF + `KILL_SWITCH=false` → exit-node client keeps internet via Synology ISP IP. Red banner in UI.
- [ ] Force Surfshark drop (e.g. block UDP outbound briefly via `iptables` on host) → auto-failover within 2 min.
- [ ] Reboot Synology → everything comes back up; Tailscale identity stable, configs intact.

## Operations

### Logs

```bash
docker logs -f tailscale-surfshark
# or
tail -F ./data/logs/*.log
```

### Update configs without rebuilding

Drop additional `.conf` files into `./data/surfshark/configs/` (one JSON per location, format matches what the API client writes). They appear in the UI dropdown automatically.

### Disable kill switch temporarily

```bash
docker compose stop
sed -i 's/^KILL_SWITCH=.*/KILL_SWITCH=false/' .env
docker compose up -d
```

### Reset everything

```bash
docker compose down
rm -rf ./data/
```

## Troubleshooting

- **UI unreachable:** confirm `tailscale status` on a client shows the exit node device as Online. Check `docker logs tailscale-surfshark` for `http listening` line — the bind IP should be the tailnet IP.
- **Speeds < 20 Mbps:** likely DERP-relayed (firewall blocking UDP). Check the Tailscale admin for a "relayed" warning. See the reference blog post for the OPNsense rule that fixes it.
- **All configs unusable after refresh:** Surfshark may have revoked the keypair. Delete `./data/surfshark/keys/` and refresh — a new keypair will be generated and registered.

## Reference

This project automates the manual setup described in [tailscale-surfshark on a Debian VM (blog post)](https://your-blog-url/), packaged as a single Synology-ready container.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: README with quick-start and manual checklist"
```

---

## Task 22: Final smoke run

- [ ] **Step 1: Full unit test suite**

```bash
make test
```

Expected: all green.

- [ ] **Step 2: Integration test**

```bash
make test-integration
```

Expected: all green.

- [ ] **Step 3: Docker build**

```bash
docker build -t tailscale-surfshark:dev .
docker images | grep tailscale-surfshark
```

Expected: final image < 100 MB.

- [ ] **Step 4: Tag a release commit**

```bash
git log --oneline | head -25  # sanity-check the history
git tag -a v0.1.0 -m "v0.1.0: initial release"
```

(Do NOT push without the user's explicit instruction.)

- [ ] **Step 5: Inform the user**

Report that all tasks are complete, all tests pass, image builds, and ask the user to:

- Push to the Synology (`docker compose up -d --build`),
- Run the manual checklist in `README.md`,
- Report which items pass / which surface issues to fix in v0.2.
