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
	cmd      *exec.Cmd
	frames   chan []byte
	stop     chan struct{}
	done     chan struct{}
	closed   bool
	writeErr error
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
	driver := &ProcessDriver{input: input, cmd: command, frames: make(chan []byte, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go driver.writeLoop()
	return driver, nil
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
	if d.closed {
		d.mu.Unlock()
		return errors.New("Blinkt driver is closed")
	}
	if d.writeErr != nil {
		err = d.writeErr
		d.mu.Unlock()
		return err
	}
	frames := d.frames
	stop := d.stop
	d.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-stop:
		return errors.New("Blinkt driver is closed")
	case frames <- data:
		return nil
	default:
		// Keep the newest frame. The display is advisory, so a slow GPIO
		// write must not block the Controller operation or animation loop.
		select {
		case <-frames:
		default:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stop:
			return errors.New("Blinkt driver is closed")
		case frames <- data:
			return nil
		default:
			return nil
		}
	}
}

func (d *ProcessDriver) writeLoop() {
	defer close(d.done)
	for {
		select {
		case <-d.stop:
			return
		case data := <-d.frames:
			if _, err := d.input.Write(data); err != nil {
				d.mu.Lock()
				d.writeErr = err
				d.mu.Unlock()
				return
			}
		}
	}
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
	stop := d.stop
	d.mu.Unlock()
	close(stop)
	_ = input.Close()
	<-d.done
	return command.Wait()
}
