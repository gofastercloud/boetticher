//go:build !linux

package main

import "fmt"

func reconnectStreamDeckUSB() error {
	return fmt.Errorf("StreamDeck USB driver recovery is only supported on Linux")
}
