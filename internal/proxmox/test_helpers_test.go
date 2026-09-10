package proxmox

import (
	"context"
	"io"
)

type fakeRunner struct {
	responses map[string][]byte
	address   string
	user      string
	command   string
}

func (r *fakeRunner) Run(_ context.Context, address, user, command string) ([]byte, error) {
	r.address, r.user, r.command = address, user, command
	if r.responses == nil {
		return nil, nil
	}
	return r.responses[command], nil
}

func (r *fakeRunner) RunWithStdin(ctx context.Context, address, user, command string, _ io.Reader) ([]byte, error) {
	return r.Run(ctx, address, user, command)
}
