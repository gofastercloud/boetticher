package pushover

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const testCredentials = "0123456789ABCDEFGHIJklmnopqrst"

func TestParseCredentialsStrictFormat(t *testing.T) {
	got, err := ParseCredentials([]byte(testCredentials + ":" + testCredentials + "\n"))
	if err != nil || got.User != testCredentials || got.Token != testCredentials {
		t.Fatalf("credentials=%+v err=%v", got, err)
	}
	for _, value := range []string{"one:two:three", "short:short", testCredentials + ":bad\n\n", testCredentials + ":token-with-dash-123456789012"} {
		if _, err := ParseCredentials([]byte(value)); err == nil {
			t.Fatalf("accepted invalid credentials %q", value)
		}
	}
	got, err = ParseCredentials([]byte(testCredentials + ":" + testCredentials))
	if err != nil || got.User != testCredentials || got.Token != testCredentials {
		t.Fatalf("credentials without trailing newline rejected: credentials=%+v err=%v", got, err)
	}
}

func testClient(serverURL string) Client {
	client := NewClient(nil)
	client.validateURL = serverURL + "/validate"
	client.messageURL = serverURL + "/messages"
	return client
}

type localServer struct {
	server   *http.Server
	listener net.Listener
	URL      string
}

func newIPv4Server(handler http.Handler) *localServer {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	return &localServer{server: server, listener: listener, URL: "http://" + listener.Addr().String()}
}

func (server *localServer) Close() {
	_ = server.server.Close()
	_ = server.listener.Close()
}

func TestClientRequiresPushoverStatusOneAndSendsForm(t *testing.T) {
	var validateForm, messageForm url.Values
	server := newIPv4Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(body))
		if r.URL.Path == "/validate" {
			validateForm = values
		} else {
			messageForm = values
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":1}`))
	}))
	defer server.Close()
	client := testClient(server.URL)
	credentials := Credentials{User: testCredentials, Token: testCredentials}
	if err := client.Validate(context.Background(), credentials); err != nil {
		t.Fatal(err)
	}
	if err := client.Send(context.Background(), credentials, "Boetticher test", "normal priority test", 0); err != nil {
		t.Fatal(err)
	}
	if validateForm.Get("user") != testCredentials || validateForm.Get("token") != testCredentials {
		t.Fatalf("validate form=%v", validateForm)
	}
	if messageForm.Get("title") != "Boetticher test" || messageForm.Get("message") != "normal priority test" || messageForm.Get("priority") != "0" {
		t.Fatalf("message form=%v", messageForm)
	}
}

func TestClientRejectsStatusZeroRedirectAndRedactsResponse(t *testing.T) {
	credentials := Credentials{User: testCredentials, Token: testCredentials}
	server := newIPv4Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":0,"errors":["` + testCredentials + `"]}`))
	}))
	client := testClient(server.URL)
	err := client.Validate(context.Background(), credentials)
	if err == nil || !strings.Contains(err.Error(), "reported failure") || strings.Contains(err.Error(), testCredentials) {
		t.Fatalf("status zero error=%v", err)
	}
	redirect := newIPv4Server(http.RedirectHandler(server.URL+"/target", http.StatusFound))
	defer redirect.Close()
	client.validateURL = redirect.URL
	err = client.Validate(context.Background(), credentials)
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("redirect error=%v", err)
	}
}

func TestClientDoesNotRetryMessagePost(t *testing.T) {
	calls := 0
	server := newIPv4Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("secret response body"))
	}))
	defer server.Close()
	client := testClient(server.URL)
	err := client.Send(context.Background(), Credentials{User: testCredentials, Token: testCredentials}, "test", "message", 0)
	if err == nil || calls != 1 || strings.Contains(err.Error(), "secret response body") || strings.Contains(err.Error(), testCredentials) {
		t.Fatalf("error=%v calls=%d", err, calls)
	}
}

func TestClientEnforcesPushoverMessageBoundsAndReservedPriority(t *testing.T) {
	client := NewClient(nil)
	credentials := Credentials{User: testCredentials, Token: testCredentials}
	for _, test := range []struct {
		name     string
		title    string
		message  string
		priority int
	}{
		{name: "title", title: strings.Repeat("t", 251), message: "message", priority: 0},
		{name: "message", title: "title", message: strings.Repeat("m", 1025), priority: 0},
		{name: "emergency", title: "title", message: "message", priority: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := client.Send(context.Background(), credentials, test.title, test.message, test.priority); err == nil {
				t.Fatal("invalid Pushover request was accepted")
			}
		})
	}
}
