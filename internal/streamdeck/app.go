package streamdeck

import (
	"context"
)

type DeckOpener func(context.Context, Config) (Deck, error)
