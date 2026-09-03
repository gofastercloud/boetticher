//go:build linux

package main

import (
	"strings"
	"testing"

	"github.com/gofastercloud/boetticher/internal/streamdeck"
)

func TestSelectStreamDeckUSBDeviceRequiresOneExactMatch(t *testing.T) {
	config := streamdeck.Config{VendorID: streamdeck.DefaultVendorID, ProductID: streamdeck.DefaultProductID, Model: streamdeck.DefaultModel}
	path, err := selectStreamDeckUSBDevice(config, []streamDeckUSBDevice{{VendorID: streamdeck.DefaultVendorID, ProductID: streamdeck.DefaultProductID, Bus: 1, Device: 4}})
	if err != nil || path != "/dev/bus/usb/001/004" {
		t.Fatalf("exact USB selection = %q, %v", path, err)
	}
	if _, err := selectStreamDeckUSBDevice(config, []streamDeckUSBDevice{{VendorID: streamdeck.DefaultVendorID, ProductID: streamdeck.DefaultProductID, Bus: 1, Device: 4}, {VendorID: streamdeck.DefaultVendorID, ProductID: streamdeck.DefaultProductID, Bus: 2, Device: 7}}); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous USB identity was accepted: %v", err)
	}
	if _, err := selectStreamDeckUSBDevice(config, nil); err == nil || !strings.Contains(err.Error(), "no exact") {
		t.Fatalf("missing USB identity was accepted: %v", err)
	}
}

func TestSelectStreamDeckUSBDevicePinsSerialWhenConfigured(t *testing.T) {
	config := streamdeck.Config{VendorID: streamdeck.DefaultVendorID, ProductID: streamdeck.DefaultProductID, Model: streamdeck.DefaultModel, Serial: "deck-a"}
	path, err := selectStreamDeckUSBDevice(config, []streamDeckUSBDevice{{VendorID: streamdeck.DefaultVendorID, ProductID: streamdeck.DefaultProductID, Bus: 1, Device: 4, Serial: "deck-b"}, {VendorID: streamdeck.DefaultVendorID, ProductID: streamdeck.DefaultProductID, Bus: 2, Device: 7, Serial: "deck-a"}})
	if err != nil || path != "/dev/bus/usb/002/007" {
		t.Fatalf("serial-pinned USB selection = %q, %v", path, err)
	}
	if _, err := selectStreamDeckUSBDevice(config, []streamDeckUSBDevice{{VendorID: streamdeck.DefaultVendorID, ProductID: streamdeck.DefaultProductID, Bus: 1, Device: 4, Serial: "deck-b"}}); err == nil || !strings.Contains(err.Error(), "no exact") {
		t.Fatalf("wrong serial USB identity was accepted: %v", err)
	}
}
