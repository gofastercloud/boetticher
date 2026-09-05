package streamdeck

import (
	"context"
	"errors"
	"fmt"
	"syscall"
)

type DeckOpener func(context.Context, Config) (Deck, error)

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
