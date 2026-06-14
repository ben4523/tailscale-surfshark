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
