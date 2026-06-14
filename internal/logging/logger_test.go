package logging_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ben4523/tailscale-surfshark/internal/logging"
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
