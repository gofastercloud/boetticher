//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"github.com/gofastercloud/boetticher/internal/streamdeck"
	"golang.org/x/sys/unix"
)

const (
	usbSysfsRoot    = "/sys/bus/usb/devices"
	usbDevFSRoot    = "/dev/bus/usb"
	usbDevFSConnect = 0x5517
	usbDevFSIoctl   = 0xc0105512
)

type usbFSIoctl struct {
	Interface uint32
	IoctlCode uint32
	Data      uintptr
}

type streamDeckUSBDevice struct {
	VendorID  uint16
	ProductID uint16
	Bus       int
	Device    int
	Serial    string
}

// streamDeckDevicePath resolves the device node from sysfs on every open.
// Device numbers can change after a replug, so a cached /dev path would be
// both unreliable and unsafe for a recovery operation.
func streamDeckDevicePath(config streamdeck.Config) (string, error) {
	if config.VendorID != streamdeck.DefaultVendorID || config.ProductID != streamdeck.DefaultProductID || config.Model != streamdeck.DefaultModel {
		return "", errors.New("unsupported StreamDeck USB identity")
	}
	entries, err := os.ReadDir(usbSysfsRoot)
	if err != nil {
		return "", fmt.Errorf("list StreamDeck USB sysfs devices: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	devices := make([]streamDeckUSBDevice, 0)
	for _, entry := range entries {
		deviceDir := filepath.Join(usbSysfsRoot, entry.Name())
		vendor, ok, err := readUSBHex(filepath.Join(deviceDir, "idVendor"))
		if err != nil {
			return "", err
		}
		if !ok || vendor != config.VendorID {
			continue
		}
		product, ok, err := readUSBHex(filepath.Join(deviceDir, "idProduct"))
		if err != nil {
			return "", err
		}
		if !ok || product != config.ProductID {
			continue
		}
		bus, ok, err := readUSBDecimal(filepath.Join(deviceDir, "busnum"))
		if err != nil {
			return "", err
		}
		if !ok {
			continue
		}
		dev, ok, err := readUSBDecimal(filepath.Join(deviceDir, "devnum"))
		if err != nil {
			return "", err
		}
		if !ok {
			continue
		}
		serial := readUSBText(filepath.Join(deviceDir, "serial"))
		if config.Serial != "" && serial != config.Serial {
			continue
		}
		devices = append(devices, streamDeckUSBDevice{VendorID: vendor, ProductID: product, Bus: bus, Device: dev, Serial: serial})
	}
	return selectStreamDeckUSBDevice(config, devices)
}

func selectStreamDeckUSBDevice(config streamdeck.Config, devices []streamDeckUSBDevice) (string, error) {
	if len(devices) == 0 {
		return "", fmt.Errorf("no exact StreamDeck device %04x:%04x%s is available", config.VendorID, config.ProductID, serialSuffix(config.Serial))
	}
	matches := 0
	var path string
	for _, device := range devices {
		if device.VendorID != config.VendorID || device.ProductID != config.ProductID {
			continue
		}
		if config.Serial != "" && device.Serial != config.Serial {
			continue
		}
		matches++
		path = fmt.Sprintf("%s/%03d/%03d", usbDevFSRoot, device.Bus, device.Device)
	}
	if matches == 0 {
		return "", fmt.Errorf("no exact StreamDeck device %04x:%04x%s is available", config.VendorID, config.ProductID, serialSuffix(config.Serial))
	}
	if matches != 1 {
		return "", fmt.Errorf("refusing ambiguous StreamDeck identity: %d exact devices matched", matches)
	}
	return path, nil
}

func serialSuffix(serial string) string {
	if serial == "" {
		return ""
	}
	return " serial " + serial
}

func readUSBHex(path string) (uint16, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read USB identity %s: %w", path, err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 16, 16)
	if err != nil {
		return 0, false, fmt.Errorf("parse USB identity %s: %w", path, err)
	}
	return uint16(value), true, nil
}

func readUSBDecimal(path string) (int, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read USB device number %s: %w", path, err)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || value < 1 || value > 255 {
		return 0, false, fmt.Errorf("invalid USB device number in %s", path)
	}
	return value, true, nil
}

func readUSBText(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func reconnectStreamDeckUSB(config streamdeck.Config) error {
	path, err := streamDeckDevicePath(config)
	if err != nil {
		return err
	}
	if err := reconnectUSBKernelDriver(path); err != nil {
		return fmt.Errorf("reconnect exact StreamDeck USB device: %w", err)
	}
	return nil
}

func reconnectUSBKernelDriver(path string) error {
	device, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer device.Close()
	request := usbFSIoctl{IoctlCode: usbDevFSConnect}
	raw, err := device.SyscallConn()
	if err != nil {
		return err
	}
	var ioctlErr error
	if err := raw.Control(func(fd uintptr) {
		result, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, usbDevFSIoctl, uintptr(unsafe.Pointer(&request)))
		if result == ^uintptr(0) && errno != unix.EBUSY {
			ioctlErr = errno
		}
	}); err != nil {
		return err
	}
	return ioctlErr
}
