//go:build linux

package controllerstatus

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	decklib "github.com/matthewpi/streamdeck"
	"golang.org/x/sys/unix"
)

const (
	streamDeckSysfsRoot    = "/sys/bus/usb/devices"
	streamDeckDevFSRoot    = "/dev/bus/usb"
	streamDeckDevFSConnect = 0x5517
	streamDeckDevFSIoctl   = 0xc0105512
	streamDeckVendorID     = uint16(0x0fd9)
	streamDeckProductID    = uint16(0x006d)
)

type streamDeckUSBDevice struct {
	VendorID  uint16
	ProductID uint16
	Bus       int
	Device    int
	Serial    string
}

func openNativeDeck(ctx context.Context, config StreamDeckConfig) (*decklib.Device, error) {
	path, err := streamDeckDevicePath(config)
	if err != nil {
		return nil, err
	}
	device, err := decklib.OpenPath(ctx, path)
	if errors.Is(err, syscall.ENODATA) {
		if reconnectErr := reconnectStreamDeckUSB(path); reconnectErr != nil {
			return nil, fmt.Errorf("reconnect StreamDeck USB device: %w", reconnectErr)
		}
		device, err = decklib.OpenPath(ctx, path)
	}
	if err != nil {
		return nil, err
	}
	return device, nil
}

func streamDeckDevicePath(config StreamDeckConfig) (string, error) {
	entries, err := os.ReadDir(streamDeckSysfsRoot)
	if err != nil {
		return "", fmt.Errorf("list StreamDeck USB devices: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	devices := make([]streamDeckUSBDevice, 0)
	for _, entry := range entries {
		root := filepath.Join(streamDeckSysfsRoot, entry.Name())
		vendor, ok, err := readStreamDeckHex(filepath.Join(root, "idVendor"))
		if err != nil || !ok || vendor != streamDeckVendorID {
			if err != nil {
				return "", err
			}
			continue
		}
		product, ok, err := readStreamDeckHex(filepath.Join(root, "idProduct"))
		if err != nil || !ok || product != streamDeckProductID {
			if err != nil {
				return "", err
			}
			continue
		}
		bus, ok, err := readStreamDeckDecimal(filepath.Join(root, "busnum"))
		if err != nil || !ok {
			if err != nil {
				return "", err
			}
			continue
		}
		device, ok, err := readStreamDeckDecimal(filepath.Join(root, "devnum"))
		if err != nil || !ok {
			if err != nil {
				return "", err
			}
			continue
		}
		serial := readStreamDeckText(filepath.Join(root, "serial"))
		if config.Serial != "" && serial != config.Serial {
			continue
		}
		devices = append(devices, streamDeckUSBDevice{VendorID: vendor, ProductID: product, Bus: bus, Device: device, Serial: serial})
	}
	if len(devices) == 0 {
		return "", errors.New("no exact StreamDeck device is available")
	}
	if len(devices) != 1 {
		return "", fmt.Errorf("refusing ambiguous StreamDeck identity: %d exact devices matched", len(devices))
	}
	device := devices[0]
	return fmt.Sprintf("%s/%03d/%03d", streamDeckDevFSRoot, device.Bus, device.Device), nil
}

func readStreamDeckHex(path string) (uint16, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read StreamDeck USB identity: %w", err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 16, 16)
	if err != nil {
		return 0, false, fmt.Errorf("parse StreamDeck USB identity: %w", err)
	}
	return uint16(value), true, nil
}

func readStreamDeckDecimal(path string) (int, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read StreamDeck device number: %w", err)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || value < 1 || value > 255 {
		return 0, false, errors.New("invalid StreamDeck USB device number")
	}
	return value, true, nil
}

func readStreamDeckText(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

type streamDeckUSBFSIoctl struct {
	Interface uint32
	IoctlCode uint32
	Data      uintptr
}

func reconnectStreamDeckUSB(path string) error {
	device, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer device.Close()
	request := streamDeckUSBFSIoctl{IoctlCode: streamDeckDevFSConnect}
	raw, err := device.SyscallConn()
	if err != nil {
		return err
	}
	var ioctlErr error
	if err := raw.Control(func(fd uintptr) {
		result, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, streamDeckDevFSIoctl, uintptr(unsafe.Pointer(&request)))
		if result == ^uintptr(0) && errno != unix.EBUSY {
			ioctlErr = errno
		}
	}); err != nil {
		return err
	}
	return ioctlErr
}
