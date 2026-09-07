package controllerstatus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
)

type ProcessDriver struct {
	mu    sync.Mutex
	input interface {
		Write([]byte) (int, error)
		Close() error
	}
	cmd    *exec.Cmd
	closed bool
}

func NewProcessDriver(pythonPath, helperPath string, chip int) (*ProcessDriver, error) {
	if pythonPath == "" {
		pythonPath = "/usr/bin/python3"
	}
	if helperPath == "" || chip < 0 {
		return nil, errors.New("Blinkt driver path and GPIO chip are required")
	}
	command := exec.Command(pythonPath, helperPath, "--chip", strconv.Itoa(chip))
	command.Stderr = os.Stderr
	input, err := command.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("open Blinkt driver input: %w", err)
	}
	if err := command.Start(); err != nil {
		_ = input.Close()
		return nil, fmt.Errorf("start Blinkt driver: %w", err)
	}
	return &ProcessDriver{input: input, cmd: command}, nil
}

func (d *ProcessDriver) Show(ctx context.Context, frame []Pixel) error {
	if len(frame) != PixelCount {
		return fmt.Errorf("Blinkt frame has %d pixels, want %d", len(frame), PixelCount)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	data, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("Blinkt driver is closed")
	}
	_, err = d.input.Write(data)
	return err
}

func (d *ProcessDriver) Clear(ctx context.Context) error {
	return d.Show(ctx, make([]Pixel, PixelCount))
}

func (d *ProcessDriver) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	input := d.input
	command := d.cmd
	d.mu.Unlock()
	_ = input.Close()
	return command.Wait()
}
