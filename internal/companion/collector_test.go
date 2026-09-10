package companion

import (
	"encoding/json"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"testing"
)

func TestDNSCheckCannotUseHostsFile(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 4096)
		n, peer, err := listener.ReadFrom(buffer)
		if err != nil {
			done <- err
			return
		}
		var message dnsmessage.Message
		if err = message.Unpack(buffer[:n]); err != nil {
			done <- err
			return
		}
		message.Response = true
		message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: message.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{198, 51, 100, 1}}}}
		data, err := message.Pack()
		if err == nil {
			_, err = listener.WriteTo(data, peer)
		}
		done <- err
	}()
	if err := verifyDNS(context.Background(), listener.LocalAddr().String(), "localhost", "198.51.100.1"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPercentSentinelAndUnknownAreNotZero(t *testing.T) {
	for _, raw := range []string{`-1`, `null`, `{}`, `{"unit":"bytes","value":5}`} {
		if value := percent(json.RawMessage(raw)); value != nil {
			t.Fatalf("%s became a percentage", raw)
		}
	}
}
