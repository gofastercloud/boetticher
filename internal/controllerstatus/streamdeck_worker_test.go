package controllerstatus

import (
	"context"
	"errors"
	"testing"
	"time"
)

type workerTestDeck struct {
	frames  chan []KeyImage
	events  chan KeyEvent
	cleared chan struct{}
	closed  chan struct{}
}

func newWorkerTestDeck() *workerTestDeck {
	return &workerTestDeck{
		frames:  make(chan []KeyImage, 1),
		events:  make(chan KeyEvent, 1),
		cleared: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (d *workerTestDeck) SetKey(_ context.Context, _ int, key KeyImage) error {
	select {
	case d.frames <- []KeyImage{key}:
	default:
	}
	return nil
}
func (d *workerTestDeck) Clear(context.Context) error {
	select {
	case <-d.cleared:
	default:
		close(d.cleared)
	}
	return nil
}
func (d *workerTestDeck) Events() <-chan KeyEvent { return d.events }
func (d *workerTestDeck) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	return nil
}

func TestStreamDeckWorkerOwnsWritesAndForwardsEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deck := newWorkerTestDeck()
	frames := make(chan []KeyImage, 1)
	events := make(chan KeyEvent, 1)
	done := make(chan struct{})
	go func() {
		runStreamDeck(ctx, func(context.Context) (StreamDeck, error) { return deck, nil }, frames, events, nil)
		close(done)
	}()
	frames <- []KeyImage{{Title: "HOST"}}
	select {
	case frame := <-deck.frames:
		if len(frame) != 1 || frame[0].Title != "HOST" {
			t.Fatalf("written frame = %#v", frame)
		}
	case <-time.After(time.Second):
		t.Fatal("StreamDeck frame was not written")
	}
	deck.events <- KeyEvent{Index: 14}
	select {
	case event := <-events:
		if event.Index != 14 {
			t.Fatalf("forwarded event = %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("StreamDeck event was not forwarded")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("StreamDeck worker did not stop")
	}
	select {
	case <-deck.closed:
	default:
		t.Fatal("StreamDeck was not closed")
	}
}

func TestStreamDeckWorkerTreatsAbsentDeviceAsRetryable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	frames := make(chan []KeyImage, 1)
	events := make(chan KeyEvent, 1)
	called := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		runStreamDeck(ctx, func(context.Context) (StreamDeck, error) {
			select {
			case called <- struct{}{}:
			default:
			}
			return nil, errors.New("StreamDeck absent")
		}, frames, events, nil)
		close(done)
	}()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("StreamDeck factory was not attempted")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("absent StreamDeck worker did not stop")
	}
}
