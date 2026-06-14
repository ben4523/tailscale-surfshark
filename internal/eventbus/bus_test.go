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
