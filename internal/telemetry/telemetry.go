// Package telemetry carries bounded, non-secret operation measurements through
// the deployment call graph. It deliberately has no dependency on reporting,
// configuration, or provider packages.
package telemetry

import (
	"context"
	"time"
)

// Event is a low-cardinality operation measurement. Operation and Target must
// be safe identifiers supplied by the caller; command text, arguments,
// request bodies, response bodies, and secret values do not belong here.
type Event struct {
	Category  string
	Operation string
	Target    string
	Method    string
	Status    int
	Duration  time.Duration
	Success   bool
	Changed   bool
}

// Observer receives measurements synchronously at the end of an operation.
// Implementations should be fast and must not affect the operation result.
type Observer interface {
	Observe(Event)
}

type observerKey struct{}

// WithObserver attaches an operation observer to a context.
func WithObserver(ctx context.Context, observer Observer) context.Context {
	if observer == nil {
		return ctx
	}
	return context.WithValue(ctx, observerKey{}, observer)
}

// Record sends one measurement to the observer, if present. Reporting is
// intentionally best effort and cannot change the operation result.
func Record(ctx context.Context, event Event) {
	if ctx == nil {
		return
	}
	observer, _ := ctx.Value(observerKey{}).(Observer)
	if observer != nil {
		observer.Observe(event)
	}
}
