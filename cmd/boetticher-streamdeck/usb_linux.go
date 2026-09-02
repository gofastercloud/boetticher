//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	streamDeckVendorID  = 0x0fd9
	streamDeckV2Product = 0x006d
	usbDevFSConnect     = 0x5517
	usbDevFSIoctl       = 0xc0105512
)

type usbFSIoctl struct {
	Interface uint32
	IoctlCode uint32
	Data      uintptr
}

func reconnectStreamDeckUSB() error {
	paths, err := filepath.Glob("/dev/bus/usb/*/*")
	if err != nil {
		return fmt.Errorf("list USB devices: %w", err)
	}
	for _, path := range paths {
		descriptor, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read USB descriptor %s: %w", path, err)
		}
		if !streamDeckV2Descriptor(descriptor) {
			continue
		}
		if err := reconnectUSBKernelDriver(path); err != nil {
			return fmt.Errorf("reconnect StreamDeck USB driver at %s: %w", path, err)
		}
		return nil
	}
	return fmt.Errorf("no supported StreamDeck USB device is available")
}

func streamDeckV2Descriptor(descriptor []byte) bool {
	return len(descriptor) >= 12 && binary.LittleEndian.Uint16(descriptor[8:10]) == streamDeckVendorID && binary.LittleEndian.Uint16(descriptor[10:12]) == streamDeckV2Product
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
