package main

import (
	"context"
	"errors"
	"syscall"
	"testing"

	decklib "github.com/matthewpi/streamdeck"
)

func TestOpenRawDeckRecoversAnUnboundUSBInterface(t *testing.T) {
	expected := errors.New("second open")
	attempts, repairs := 0, 0
	_, err := openRawDeck(context.Background(), func(context.Context) (*decklib.Device, error) {
		attempts++
		if attempts == 1 {
			return nil, syscall.ENODATA
		}
		return nil, expected
	}, func() error {
		repairs++
		return nil
	})
	if !errors.Is(err, expected) {
		t.Fatalf("open error = %v, want second attempt error", err)
	}
	if attempts != 2 || repairs != 1 {
		t.Fatalf("attempts=%d repairs=%d, want 2 and 1", attempts, repairs)
	}
}

func TestOpenRawDeckDoesNotRecoverOtherErrors(t *testing.T) {
	expected := errors.New("permission denied")
	attempts, repairs := 0, 0
	_, err := openRawDeck(context.Background(), func(context.Context) (*decklib.Device, error) {
		attempts++
		return nil, expected
	}, func() error {
		repairs++
		return nil
	})
	if !errors.Is(err, expected) {
		t.Fatalf("open error = %v, want original error", err)
	}
	if attempts != 1 || repairs != 0 {
		t.Fatalf("attempts=%d repairs=%d, want 1 and 0", attempts, repairs)
	}
}

func TestOpenRawDeckFailsClosedWhenUSBRecoveryFails(t *testing.T) {
	recoveryErr := errors.New("reconnect failed")
	attempts, repairs := 0, 0
	_, err := openRawDeck(context.Background(), func(context.Context) (*decklib.Device, error) {
		attempts++
		return nil, syscall.ENODATA
	}, func() error {
		repairs++
		return recoveryErr
	})
	if !errors.Is(err, recoveryErr) {
		t.Fatalf("open error = %v, want recovery error", err)
	}
	if attempts != 1 || repairs != 1 {
		t.Fatalf("attempts=%d repairs=%d, want 1 and 1", attempts, repairs)
	}
}
