package watchdog_test

import (
	"testing"

	"github.com/ben4523/tailscale-surfshark/internal/watchdog"
)

func TestPickNextCandidate_UsesPreferredFirst(t *testing.T) {
	got := watchdog.NextCandidate("us-nyc", []string{"us-nyc", "us-bos", "fr-par"}, []string{"us-nyc", "us-bos", "fr-par", "de-ber"})
	if got != "us-bos" {
		t.Errorf("got %q, want us-bos", got)
	}
}

func TestPickNextCandidate_FallsBackToAlphabeticalNeighbors(t *testing.T) {
	got := watchdog.NextCandidate("us-nyc", nil, []string{"us-bos", "us-mia", "us-nyc", "us-sjc", "fr-par"})
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
