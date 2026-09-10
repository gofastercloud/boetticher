package streamdeck

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gofastercloud/boetticher/internal/companion"
)

func TestConsoleNavigationRemainsInBottomRow(t *testing.T) {
	s := companion.NewState(companion.Config{})
	home := ConsoleTiles(s.Snapshot())
	_ = s.Action("select", "resources")
	resources := ConsoleTiles(s.Snapshot())
	for i, action := range []string{"home", "back", "previous", "next", "dim"} {
		if home[10+i].Action != action || resources[10+i] != home[10+i] {
			t.Fatal("navigation moved")
		}
	}
	if home[3].Target != "dns" || home[9].Action != "refresh" {
		t.Fatal("wrong local actions")
	}
}

func TestRunConsoleKeepsRetryingWhenStreamDeckIsAbsent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	err := RunConsole(ctx, Config{
		VendorID:  DefaultVendorID,
		ProductID: DefaultProductID,
		Model:     DefaultModel,
	}, func(context.Context, Config) (Deck, error) {
		return nil, errors.New("StreamDeck not present")
	})
	if err != nil {
		t.Fatalf("missing StreamDeck blocked the console: %v", err)
	}
}
