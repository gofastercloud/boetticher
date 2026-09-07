package openwrt

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestClientAuthenticatesAndReadsActualUCIJSONRPC(t *testing.T) {
	requests := 0
	client := testClient(func(r *http.Request) (*http.Response, error) {
		requests++
		method, params, err := requestParts(r)
		if err != nil {
			return nil, err
		}
		if method != "call" || len(params) != 4 {
			return nil, &unexpectedMethodError{method: method}
		}
		switch stringParam(params[2]) {
		case "login":
			return response(`{"jsonrpc":"2.0","id":1,"result":[0,{"ubus_rpc_session":"session-1"}]}`), nil
		case "get":
			return response(`{"jsonrpc":"2.0","id":2,"result":[0,{"values":{"boetticher_iface_trusted":{".type":"interface",".name":"boetticher_iface_trusted","proto":"static","ipaddr":"10.10.30.1","dns":["10.10.30.1"]},"operator_record":{".type":"rule",".name":"operator_record","target":"ACCEPT"}}}]}`), nil
		default:
			return nil, &unexpectedMethodError{method: stringParam(params[2])}
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

func TestClientUCIWritesActualValuesObjects(t *testing.T) {
	var methods []string
	var params []map[string]any
	client := testClient(func(r *http.Request) (*http.Response, error) {
		_, rawParams, err := requestParts(r)
		if err != nil {
			return nil, err
		}
		methods = append(methods, stringParam(rawParams[2]))
		var object map[string]any
		if err := json.Unmarshal(rawParams[3], &object); err != nil {
			return nil, err
		}
		params = append(params, object)
		if stringParam(rawParams[2]) == "login" {
			return response(`{"jsonrpc":"2.0","id":1,"result":[0,{"ubus_rpc_session":"session-1"}]}`), nil
		}
		if stringParam(rawParams[2]) == "add" {
			section := "anonymous"
			var addParams map[string]any
			if err := json.Unmarshal(rawParams[3], &addParams); err != nil {
				return nil, err
			}
			if requested, ok := addParams["name"].(string); ok {
				section = requested
			}
			return response(`{"jsonrpc":"2.0","id":2,"result":[0,{"section":"` + section + `"}]}`), nil
		}
		return response(`{"jsonrpc":"2.0","id":2,"result":[0]}`), nil
	})
	if _, err := client.UCIAdd(context.Background(), "network", "interface"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.UCIAddNamed(context.Background(), "network", "interface", "named-section"); err != nil {
		t.Fatal(err)
	}
	if err := client.UCISet(context.Background(), "network", "section-1", "proto", "static"); err != nil {
		t.Fatal(err)
	}
	if err := client.UCISetList(context.Background(), "network", "section-1", "device", []string{"br-lab.30", "br-lab.99"}); err != nil {
		t.Fatal(err)
	}
	if err := client.UCIDelete(context.Background(), "network", "section-1", "old"); err != nil {
		t.Fatal(err)
	}
	if err := client.UCIApply(context.Background(), 30); err != nil {
		t.Fatal(err)
	}
	if strings.Join(methods, ",") != "login,add,add,set,set,delete,apply" {
		t.Fatalf("UCI methods = %v", methods)
	}
	if params[2]["name"] != "named-section" {
		t.Fatalf("uci.add named section payload = %#v", params[2])
	}
	if _, hasOption := params[3]["option"]; hasOption {
		t.Fatalf("uci.set retained retired option/value shape: %#v", params[3])
	}
	values, ok := params[4]["values"].(map[string]any)
	if !ok || len(values) != 1 {
		t.Fatalf("uci.set list values = %#v", params[4])
	}
	list, ok := values["device"].([]any)
	if !ok || len(list) != 2 {
		t.Fatalf("uci.set list payload = %#v", params[4])
	}
}

func TestClientRejectsAuthenticationFailureWithoutLeakingPassword(t *testing.T) {
	client := testClient(func(*http.Request) (*http.Response, error) {
		return response(`{"jsonrpc":"2.0","id":1,"result":[6]}`), nil
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

func TestClientReadsDefaultRouteState(t *testing.T) {
	client := testClient(func(r *http.Request) (*http.Response, error) {
		method, params, err := requestParts(r)
		if err != nil || method != "call" {
			return nil, err
		}
		switch stringParam(params[2]) {
		case "login":
			return response(`{"jsonrpc":"2.0","id":1,"result":[0,{"ubus_rpc_session":"session-1"}]}`), nil
		case "dump":
			return response(`{"jsonrpc":"2.0","id":3,"result":[0,{"interface":[{"interface":"boetticher_home","route":[{"target":"0.0.0.0","mask":0,"nexthop":"192.168.4.1"}]}]}]}`), nil
		default:
			return nil, &unexpectedMethodError{method: stringParam(params[2])}
		}
	})
	runtime, err := client.InterfaceDump(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	route, err := DefaultRouteActive(runtime)
	if err != nil || !route {
		t.Fatalf("default route active=%t err=%v", route, err)
	}
	wrongGateway, err := DefaultRouteVia(runtime, "192.168.4.254")
	if err != nil || wrongGateway {
		t.Fatalf("unexpected default route via wrong gateway=%t err=%v", wrongGateway, err)
	}
	correctGateway, err := DefaultRouteVia(runtime, "192.168.4.1")
	if err != nil || !correctGateway {
		t.Fatalf("default route via expected gateway=%t err=%v", correctGateway, err)
	}
}

func testClient(roundTrip roundTripFunc) *Client {
	return &Client{baseURL: "https://provider.example/ubus", user: "boetticher", pass: "test-only", http: &http.Client{Transport: roundTrip}}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type unexpectedMethodError struct{ method string }

func (e *unexpectedMethodError) Error() string { return "unexpected ubus method " + e.method }

func requestParts(r *http.Request) (string, []json.RawMessage, error) {
	var input struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		return "", nil, err
	}
	return input.Method, input.Params, nil
}

func stringParam(value json.RawMessage) string {
	var result string
	_ = json.Unmarshal(value, &result)
	return result
}

func response(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
