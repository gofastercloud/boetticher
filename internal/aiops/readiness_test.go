package aiops

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fixedReadiness struct {
	pulseErr   error
	journalErr error
}

func (f fixedReadiness) CheckPulse(context.Context) error   { return f.pulseErr }
func (f fixedReadiness) CheckJournal(context.Context) error { return f.journalErr }

func TestDoctorExercisesFixedReadinessPathsAndModelAlias(t *testing.T) {
	requests := 0
	router := &http.Client{Transport: qualifyTransport(func(request *http.Request) (*http.Response, error) {
		requests++
		body := `{"choices":[{"message":{"content":"","tool_calls":[{"id":"call-1","type":"function","function":{"name":"qualification_probe","arguments":"{\"nonce\":\"boetticher-aiops-v1\"}"}}]}}]}`
		if requests == 2 {
			body = `{"choices":[{"message":{"content":"{\"status\":\"qualified\"}"}}]}`
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: request}, nil
	})}
	broker := &Broker{Readiness: fixedReadiness{}, Router: router, RouterURL: "https://ai.example.test/v1/chat/completions", ModelAlias: "operations-investigator"}
	request := httptest.NewRequest(http.MethodGet, "/v1/doctor", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	response := httptest.NewRecorder()
	broker.EvidenceHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("doctor status = %d body=%s", response.Code, response.Body.String())
	}
	var status ReadinessStatus
	if err := strictDecode(response.Body, &status); err != nil {
		t.Fatal(err)
	}
	if !status.Healthy() || status.ModelAlias != "operations-investigator" || requests != 2 {
		t.Fatalf("readiness = %#v router requests=%d", status, requests)
	}
}

func TestDoctorFailsClosedWithoutLeakingUpstreamErrors(t *testing.T) {
	broker := &Broker{Readiness: fixedReadiness{pulseErr: errors.New("credential detail"), journalErr: errors.New("host detail")}}
	request := httptest.NewRequest(http.MethodGet, "/v1/doctor", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	response := httptest.NewRecorder()
	broker.EvidenceHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "detail") {
		t.Fatalf("doctor response = %d body=%s", response.Code, response.Body.String())
	}
	var status ReadinessStatus
	if err := strictDecode(response.Body, &status); err != nil {
		t.Fatal(err)
	}
	if status.Healthy() || status.Checks[ReadinessPulse] != "FAIL" || status.Checks[ReadinessJournal] != "FAIL" || status.Checks[ReadinessRouter] != "FAIL" {
		t.Fatalf("readiness = %#v", status)
	}
}
