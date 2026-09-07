package openwrt

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestClientAuthenticatesAndReadsUCI(t *testing.T) {
	requests := 0
	client := testClient(func(r *http.Request) (*http.Response, error) {
		requests++
		var input []any
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			return nil, err
		}
		method, _ := input[4].(string)
		switch method {
		case "login":
			return response(`[2,1,0,{"ubus_rpc_session":"session-1"}]`), nil
		case "get":
			return response(`[2,2,0,{"values":{"boetticher_iface_trusted":{".type":"interface","proto":"static","ipaddr":"10.10.30.1","dns":["10.10.30.1"]},"operator_record":{".type":"rule","target":"ACCEPT"}}}]`), nil
		default:
			return nil, &unexpectedMethodError{method: method}
		}
	})
	sections, err := client.UCIGet(context.Background(), "network")
	if err != nil {
		t.Fatal(err)
	}
	if sections["boetticher_iface_trusted"].Options["ipaddr"] != "10.10.30.1" || len(sections["boetticher_iface_trusted"].Lists["dns"]) != 1 {
		t.Fatalf("unexpected UCI sections: %#v", sections)
	}
	if _, ok := sections["operator_record"]; !ok {
		t.Fatal("unrelated UCI section was not read")
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want login and read", requests)
	}
}

func TestClientUCIWriteOperationsUseTypedMethods(t *testing.T) {
	var methods []string
	client := testClient(func(r *http.Request) (*http.Response, error) {
		var input []any
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			return nil, err
		}
		method, _ := input[4].(string)
		methods = append(methods, method)
		if method == "login" {
			return response(`[2,1,0,{"ubus_rpc_session":"session-1"}]`), nil
		}
		if method == "add" {
			return response(`[2,2,0,"section-1"]`), nil
		}
		return response(`[2,2,0,{}]`), nil
	})
	if _, err := client.UCIAdd(context.Background(), "network", "interface"); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []func() error{
		func() error { return client.UCISet(context.Background(), "network", "section-1", "proto", "static") },
		func() error {
			return client.UCIAddList(context.Background(), "network", "section-1", "device", "br-lab.30")
		},
		func() error { return client.UCIDelete(context.Background(), "network", "section-1", "old") },
		func() error { return client.UCICommit(context.Background(), "network") },
		func() error { return client.UCIApply(context.Background(), 30) },
	} {
		if err := operation(); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(methods, ",") != "login,add,set,add_list,delete,commit,apply" {
		t.Fatalf("UCI methods = %v", methods)
	}
}

func TestClientRejectsAuthenticationFailureWithoutLeakingPassword(t *testing.T) {
	client := testClient(func(*http.Request) (*http.Response, error) {
		return response(`[2,1,6,{"message":"invalid credentials"}]`), nil
	})
	client.pass = "secret-not-for-output"
	err := client.Authenticate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "authentication failed") || strings.Contains(err.Error(), "secret-not-for-output") {
		t.Fatalf("unexpected authentication error: %v", err)
	}
}

func TestClientRejectsMalformedProviderResponse(t *testing.T) {
	client := testClient(func(*http.Request) (*http.Response, error) { return response(`not-json`), nil })
	if err := client.Authenticate(context.Background()); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed response was accepted: %v", err)
	}
}

func TestClientPropagatesProviderTransportFailure(t *testing.T) {
	client := testClient(func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded })
	err := client.Authenticate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("transport failure was not surfaced: %v", err)
	}
}

func TestNewClientRequiresPinnedHTTPS(t *testing.T) {
	for _, config := range []Config{
		{BaseURL: "http://127.0.0.1", Username: "u", Password: "p", TrustPEM: []byte("x")},
		{BaseURL: "https://127.0.0.1", Username: "u", Password: "p"},
	} {
		if _, err := NewClient(config); err == nil {
			t.Fatal("unsafe provider client configuration was accepted")
		}
	}
}

func TestClientReadsFirewallServiceAndDefaultRouteState(t *testing.T) {
	client := testClient(func(r *http.Request) (*http.Response, error) {
		var input []any
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			return nil, err
		}
		method, _ := input[4].(string)
		switch method {
		case "login":
			return response(`[2,1,0,{"ubus_rpc_session":"session-1"}]`), nil
		case "list":
			return response(`[2,2,0,{"firewall":{"instances":{"firewall":{"running":true}}}}]`), nil
		case "dump":
			return response(`[2,3,0,{"interface":[{"interface":"boetticher_home","route":[{"target":"0.0.0.0","mask":0,"nexthop":"192.168.4.1"}]}]}]`), nil
		default:
			return nil, &unexpectedMethodError{method: method}
		}
	})
	active, err := client.ServiceRunning(context.Background(), "firewall")
	if err != nil || !active {
		t.Fatalf("firewall service active=%t err=%v", active, err)
	}
	runtime, err := client.InterfaceDump(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	route, err := DefaultRouteActive(runtime)
	if err != nil || !route {
		t.Fatalf("default route active=%t err=%v", route, err)
	}
}

func testClient(roundTrip roundTripFunc) *Client {
	return &Client{baseURL: "https://provider.example/ubus", user: "boetticher", pass: "test-only", http: &http.Client{Transport: roundTrip}}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type unexpectedMethodError struct{ method string }

func (e *unexpectedMethodError) Error() string { return "unexpected ubus method " + e.method }

func response(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
