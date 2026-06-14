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
