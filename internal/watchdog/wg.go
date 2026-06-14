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
	// Preferred list exhausted (or empty) — fall back to alphabetical neighbours.
	sorted := append([]string(nil), available...)
	sort.Strings(sorted)
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
