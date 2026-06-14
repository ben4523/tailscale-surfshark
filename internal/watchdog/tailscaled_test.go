package watchdog_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ben4523/tailscale-surfshark/internal/watchdog"
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
