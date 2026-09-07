//go:build linux

package controllerstatus

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	decklib "github.com/matthewpi/streamdeck"
	"golang.org/x/sys/unix"
)

const (
	streamDeckSysfsRoot       = "/sys/bus/usb/devices"
	streamDeckDevFSRoot       = "/dev/bus/usb"
	streamDeckDevFSDisconnect = 0x5516
	streamDeckDevFSConnect    = 0x5517
	streamDeckDevFSIoctl      = 0xc0105512
	streamDeckDevFSClaim      = 0x8004550f
	streamDeckDevFSRelease    = 0x80045510
	streamDeckDevFSBulk       = 0xc0185502
	streamDeckDevFSControl    = 0xc0185500
	streamDeckVendorID        = uint16(0x0fd9)
	streamDeckProductID       = uint16(0x006d)
)

type streamDeckUSBDevice struct {
	VendorID  uint16
	ProductID uint16
	Bus       int
	Device    int
	Serial    string
}

func openNativeStreamDeck(ctx context.Context, config StreamDeckConfig, brightness float64) (StreamDeck, error) {
	path, err := streamDeckDevicePath(config)
	if err != nil {
		return nil, err
	}
	descriptor, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read StreamDeck USB descriptor: %w", err)
	}
	info, err := parseStreamDeckUSBDescriptor(descriptor)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open StreamDeck USB device: %w", err)
	}
	device := &nativeStreamDeck{
		file: file,
		info: info,
		deviceType: decklib.DeviceType{
			Name:        "Stream Deck MK.2",
			ProductID:   streamDeckProductID,
			Rows:        3,
			Cols:        5,
			ImageFormat: decklib.JPEG,
			ImageSize:   72,
			ImageFlags:  decklib.ImageFlagFlipX | decklib.ImageFlagFlipY,
		},
		events: make(chan KeyEvent, 16),
	}
	if err := device.claim(); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("claim StreamDeck USB interface: %w", err)
	}
	value := uint8(brightness * 100)
	if value == 0 {
		value = 1
	}
	if value > 100 {
		value = 100
	}
	controlCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	_ = device.setBrightness(controlCtx, value)
	cancel()
	inputCtx, cancelInput := context.WithCancel(ctx)
	device.cancel = cancelInput
	device.wg.Add(1)
	go device.readEvents(inputCtx)
	return device, nil
}

type streamDeckUSBInfo struct {
	VendorID    uint16
	ProductID   uint16
	Interface   uint8
	EndpointIn  uint8
	EndpointOut uint8
}

func parseStreamDeckUSBDescriptor(data []byte) (streamDeckUSBInfo, error) {
	var info streamDeckUSBInfo
	hidInterface := false
	for offset := 0; offset < len(data); {
		if len(data)-offset < 2 {
			return streamDeckUSBInfo{}, errors.New("StreamDeck USB descriptor is truncated")
		}
		length := int(data[offset])
		if length < 2 || offset+length > len(data) {
			return streamDeckUSBInfo{}, errors.New("StreamDeck USB descriptor has an invalid length")
		}
		descriptor := data[offset : offset+length]
		switch descriptor[1] {
		case 1:
			if length >= 12 {
				info.VendorID = binary.LittleEndian.Uint16(descriptor[8:10])
				info.ProductID = binary.LittleEndian.Uint16(descriptor[10:12])
			}
		case 4:
			hidInterface = length >= 6 && descriptor[5] == 3
			if hidInterface {
				info.Interface = descriptor[2]
			}
		case 5:
			if hidInterface && length >= 7 {
				endpoint := descriptor[2]
				if endpoint&0x80 != 0 {
					info.EndpointIn = endpoint
				} else {
					info.EndpointOut = endpoint
				}
			}
		}
		offset += length
	}
	if info.VendorID != streamDeckVendorID || info.ProductID != streamDeckProductID {
		return streamDeckUSBInfo{}, errors.New("USB device is not the supported StreamDeck MK.2")
	}
	if info.EndpointIn == 0 {
		return streamDeckUSBInfo{}, errors.New("StreamDeck USB input endpoint is missing")
	}
	return info, nil
}

type nativeStreamDeck struct {
	file       *os.File
	info       streamDeckUSBInfo
	deviceType decklib.DeviceType
	events     chan KeyEvent
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.Mutex
	closeOnce  sync.Once
	closeErr   error
}

func (d *nativeStreamDeck) claim() error {
	disconnect := streamDeckUSBFSIoctl{Interface: uint32(d.info.Interface), IoctlCode: streamDeckDevFSDisconnect}
	if err := d.ioctl(streamDeckDevFSIoctl, uintptr(unsafe.Pointer(&disconnect))); err != nil && !errors.Is(err, syscall.ENODATA) {
		return err
	}
	interfaceNumber := uint32(d.info.Interface)
	return d.ioctl(streamDeckDevFSClaim, uintptr(unsafe.Pointer(&interfaceNumber)))
}

func (d *nativeStreamDeck) ioctl(request uintptr, argument uintptr) error {
	if d.file == nil {
		return errors.New("StreamDeck USB device is closed")
	}
	result, _, errno := unix.Syscall(unix.SYS_IOCTL, d.file.Fd(), request, argument)
	if result == ^uintptr(0) {
		return errno
	}
	return nil
}

type streamDeckUSBFSControl struct {
	ReqType uint8
	Req     uint8
	Value   uint16
	Index   uint16
	Length  uint16
	Timeout uint32
	Data    uintptr
}

type streamDeckUSBFSBulk struct {
	Endpoint uint32
	Length   uint32
	Data     uintptr
	Timeout  uint32
}

func (d *nativeStreamDeck) control(ctx context.Context, value uint16, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	request := streamDeckUSBFSControl{ReqType: 0x21, Req: 0x09, Value: value, Index: uint16(d.info.Interface), Length: uint16(len(data)), Timeout: 1000, Data: uintptr(unsafe.Pointer(&data[0]))}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ioctl(streamDeckDevFSControl, uintptr(unsafe.Pointer(&request)))
}

func (d *nativeStreamDeck) bulk(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	request := streamDeckUSBFSBulk{Endpoint: uint32(d.info.EndpointIn), Length: uint32(len(data)), Data: uintptr(unsafe.Pointer(&data[0])), Timeout: 1000}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ioctl(streamDeckDevFSBulk, uintptr(unsafe.Pointer(&request)))
}

func (d *nativeStreamDeck) setBrightness(ctx context.Context, value uint8) error {
	data := make([]byte, 32)
	data[0], data[1], data[2] = 3, 8, value
	return d.control(ctx, 0x0303, data)
}

func (d *nativeStreamDeck) write(ctx context.Context, data []byte) error {
	if d.info.EndpointOut != 0 {
		request := streamDeckUSBFSBulk{Endpoint: uint32(d.info.EndpointOut), Length: uint32(len(data)), Data: uintptr(unsafe.Pointer(&data[0])), Timeout: 1000}
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.ioctl(streamDeckDevFSBulk, uintptr(unsafe.Pointer(&request)))
	}
	return d.control(ctx, 0x0200, data)
}

func (d *nativeStreamDeck) writeImage(ctx context.Context, index int, data []byte) error {
	const (
		packetSize = 1024
		headerSize = 8
	)
	for page, offset := 0, 0; offset < len(data); page++ {
		chunkSize := len(data) - offset
		if chunkSize > packetSize-headerSize {
			chunkSize = packetSize - headerSize
		}
		packet := make([]byte, packetSize)
		packet[0], packet[1], packet[2] = 2, 7, byte(index)
		if chunkSize == len(data)-offset {
			packet[3] = 1
		}
		packet[4] = byte(chunkSize)
		packet[5] = byte(chunkSize >> 8)
		packet[6] = byte(page)
		packet[7] = byte(page >> 8)
		copy(packet[headerSize:], data[offset:offset+chunkSize])
		if err := d.write(ctx, packet); err != nil {
			return err
		}
		offset += chunkSize
	}
	return nil
}

func (d *nativeStreamDeck) SetKey(ctx context.Context, index int, key KeyImage) error {
	if index < 0 || index >= StreamDeckKeyCount {
		return fmt.Errorf("invalid StreamDeck key index: %d", index)
	}
	if key.Image == nil {
		return errors.New("StreamDeck key image is missing")
	}
	data, err := d.deviceType.EncodeImage(key.Image)
	if err != nil {
		return err
	}
	return d.writeImage(ctx, index, data)
}

func (d *nativeStreamDeck) Clear(ctx context.Context) error {
	data, err := d.deviceType.EncodeImage(image.NewRGBA(image.Rect(0, 0, 72, 72)))
	if err != nil {
		return err
	}
	for index := 0; index < StreamDeckKeyCount; index++ {
		if err := d.writeImage(ctx, index, data); err != nil {
			return err
		}
	}
	return nil
}

func (d *nativeStreamDeck) Events() <-chan KeyEvent { return d.events }

func (d *nativeStreamDeck) readEvents(ctx context.Context) {
	defer d.wg.Done()
	if d.info.EndpointIn == 0 {
		return
	}
	data := make([]byte, 512)
	for {
		if err := d.bulk(ctx, data); err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		for index := 0; index < StreamDeckKeyCount && 4+index < len(data); index++ {
			if data[4+index] == 0 {
				continue
			}
			select {
			case d.events <- KeyEvent{Index: index}:
			default:
			}
		}
	}
}

func (d *nativeStreamDeck) Close() error {
	d.closeOnce.Do(func() {
		if d.cancel != nil {
			d.cancel()
		}
		d.wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if d.file != nil {
			if err := d.setBrightness(ctx, 100); err != nil {
				d.closeErr = err
			}
			d.release()
			if err := d.file.Close(); err != nil && d.closeErr == nil {
				d.closeErr = err
			}
		}
		cancel()
	})
	return d.closeErr
}

func (d *nativeStreamDeck) release() {
	interfaceNumber := uint32(d.info.Interface)
	_ = d.ioctl(streamDeckDevFSRelease, uintptr(unsafe.Pointer(&interfaceNumber)))
	connect := streamDeckUSBFSIoctl{Interface: uint32(d.info.Interface), IoctlCode: streamDeckDevFSConnect}
	_ = d.ioctl(streamDeckDevFSIoctl, uintptr(unsafe.Pointer(&connect)))
}

var _ StreamDeck = (*nativeStreamDeck)(nil)

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
