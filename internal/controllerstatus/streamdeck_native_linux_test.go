//go:build linux

package controllerstatus

import (
	"testing"
	"unsafe"
)

func TestParseStreamDeckUSBDescriptorFindsHIDEndpoints(t *testing.T) {
	descriptor := []byte{
		18, 1, 0, 2, 0, 0, 0, 64, 0xfd, 0x0f, 0x6d, 0x00, 0, 0, 0, 0, 0, 1,
		9, 2, 32, 0, 1, 1, 0, 0, 0,
		9, 4, 0, 0, 2, 3, 0, 0, 0,
		9, 0x21, 0x11, 0x01, 0, 1, 0x22, 0x40, 0,
		7, 5, 0x81, 3, 64, 0, 1,
		7, 5, 0x02, 3, 64, 0, 1,
	}
	info, err := parseStreamDeckUSBDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if info.VendorID != streamDeckVendorID || info.ProductID != streamDeckProductID || info.Interface != 0 || info.EndpointIn != 0x81 || info.EndpointOut != 0x02 {
		t.Fatalf("parsed StreamDeck USB info = %#v", info)
	}
}

func TestParseStreamDeckUSBDescriptorRejectsInvalidDevice(t *testing.T) {
	if _, err := parseStreamDeckUSBDescriptor([]byte{18, 1}); err == nil {
		t.Fatal("truncated USB descriptor was accepted")
	}
}

func TestStreamDeckUSBFSBulkMatchesKernelLayout(t *testing.T) {
	if unsafe.Offsetof(streamDeckUSBFSBulk{}.Endpoint) != 0 || unsafe.Offsetof(streamDeckUSBFSBulk{}.Length) != 4 || unsafe.Offsetof(streamDeckUSBFSBulk{}.Timeout) != 8 || unsafe.Offsetof(streamDeckUSBFSBulk{}.Data) != 16 {
		t.Fatalf("usbdevfs bulk layout is incompatible: endpoint=%d length=%d timeout=%d data=%d", unsafe.Offsetof(streamDeckUSBFSBulk{}.Endpoint), unsafe.Offsetof(streamDeckUSBFSBulk{}.Length), unsafe.Offsetof(streamDeckUSBFSBulk{}.Timeout), unsafe.Offsetof(streamDeckUSBFSBulk{}.Data))
	}
}

func TestStreamDeckUSBFSWritesUseAReachableBoundedTimeout(t *testing.T) {
	request := streamDeckUSBFSBulk{Endpoint: 2, Length: 1024, Timeout: streamDeckUSBTimeoutMS}
	if request.Timeout == 0 || request.Timeout > 2000 {
		t.Fatalf("StreamDeck USB write timeout = %dms, want a bounded nonzero timeout", request.Timeout)
	}
}
