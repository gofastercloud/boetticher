package streamdeck

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"syscall"
	"time"
)

const (
	brightness        = 40
	pollInterval      = 5 * time.Second
	renderInterval    = time.Second
	reconnectInterval = 3 * time.Second
)

type Fetcher interface {
	Fetch(context.Context) (State, error)
}

type DeckOpener func(context.Context, string) (Deck, error)

func Run(ctx context.Context, config Config, client Fetcher, open DeckOpener) error {
	if client == nil || open == nil {
		return fmt.Errorf("StreamDeck runtime requires a Pulse client and device opener")
	}
	stateCh := make(chan State, 1)
	go poll(ctx, client, stateCh)

	var state *State
	var deck Deck
	var retry <-chan time.Time
	render := time.NewTicker(renderInterval)
	defer render.Stop()
	for {
		if deck == nil && retry == nil {
			opened, err := open(ctx, config.Serial)
			if err == nil && opened == nil {
				err = fmt.Errorf("StreamDeck opener returned no device")
			}
			if err != nil {
				slog.Warn("StreamDeck disconnected", "error", errorName(err))
				timer := time.NewTimer(reconnectInterval)
				retry = timer.C
			} else {
				if err := opened.SetBrightness(ctx, brightness); err != nil {
					_ = opened.Close(context.Background())
					slog.Warn("StreamDeck brightness setup failed", "error", errorName(err))
					timer := time.NewTimer(reconnectInterval)
					retry = timer.C
				} else {
					deck = opened
					slog.Info("StreamDeck connected")
				}
			}
		}

		select {
		case <-ctx.Done():
			if deck != nil {
				_ = deck.Close(context.Background())
			}
			return nil
		case next := <-stateCh:
			state = &next
		case <-render.C:
			if deck != nil {
				if err := Render(ctx, deck, state); err != nil {
					slog.Warn("StreamDeck disconnected", "error", errorName(err))
					_ = deck.Close(context.Background())
					deck = nil
				}
			}
		case <-retry:
			retry = nil
		}
	}
}

func poll(ctx context.Context, client Fetcher, output chan<- State) {
	var previous *State
	for {
		state, err := client.Fetch(ctx)
		if err != nil {
			if previous != nil {
				stale := *previous
				stale.Stale = errorName(err)
				select {
				case output <- stale:
				default:
				}
			}
		} else {
			previous = &state
			select {
			case output <- state:
			default:
			}
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func errorName(err error) string {
	if err == nil {
		return ""
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return fmt.Sprintf("errno=%d (%s)", errno, errno)
	}
	return fmt.Sprintf("%T", err)
}
