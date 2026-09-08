package controllerstatus

import (
	"context"
	"sync"
	"testing"
	"time"
)

type blockingBlinktWriter struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (w *blockingBlinktWriter) Write(data []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.closed
	return len(data), nil
}

func (w *blockingBlinktWriter) Close() error {
	select {
	case <-w.closed:
	default:
		close(w.closed)
	}
	return nil
}

func TestProcessDriverShowCoalescesBehindSlowGPIOWriter(t *testing.T) {
	writer := &blockingBlinktWriter{started: make(chan struct{}), closed: make(chan struct{})}
	driver := &ProcessDriver{input: writer, frames: make(chan []byte, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go driver.writeLoop()

	frame := make([]Pixel, PixelCount)
	if err := driver.Show(context.Background(), frame); err != nil {
		t.Fatalf("first Blinkt frame failed: %v", err)
	}
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("Blinkt writer did not receive the first frame")
	}

	finished := make(chan error, 1)
	go func() { finished <- driver.Show(context.Background(), frame) }()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("coalesced Blinkt frame failed: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Blinkt Show blocked behind a slow GPIO writer")
	}

	close(writer.closed)
	close(driver.stop)
	<-driver.done
}
