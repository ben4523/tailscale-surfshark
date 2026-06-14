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
