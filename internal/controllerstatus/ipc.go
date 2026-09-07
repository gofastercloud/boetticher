package controllerstatus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

func ValidateEvent(event OperationEvent) error {
	switch event.Event {
	case "operation-start", "operation-progress", "operation-success", "operation-failure":
	default:
		return fmt.Errorf("unknown status operation event %q", event.Event)
	}
	if strings.TrimSpace(event.Name) == "" || len(event.Name) > 128 {
		return errors.New("status operation event name is required and must be short")
	}
	if len(event.Detail) > 512 {
		return errors.New("status operation event detail is too long")
	}
	if event.CurrentStep < 0 || event.CurrentStep > PixelCount*16 || event.totalSteps() > PixelCount*16 {
		return errors.New("status operation event has an invalid step range")
	}
	return nil
}

func Notify(ctx context.Context, socketPath string, event OperationEvent) error {
	if err := ValidateEvent(event); err != nil {
		return err
	}
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	dialer := net.Dialer{Timeout: 250 * time.Millisecond}
	connection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	return json.NewEncoder(connection).Encode(event)
}

// NotifyBestEffort is deliberately non-failing. Display progress is advisory
// and must never gate a Controller, Host, or Module operation.
func NotifyBestEffort(event OperationEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_ = Notify(ctx, DefaultSocketPath, event)
}
