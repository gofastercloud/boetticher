// Package pushover provides the narrow Pushover validation and message API
// used by the optional observability alert contact.
package pushover

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	CredentialName   = "pushover-credentials"
	validateEndpoint = "https://api.pushover.net/1/users/validate.json"
	messageEndpoint  = "https://api.pushover.net/1/messages.json"
	keyLength        = 30
	maxResponseBytes = 64 * 1024
	maxTitleChars    = 250
	maxMessageChars  = 1024
)

type Credentials struct {
	User  string
	Token string
}

func ParseCredentials(raw []byte) (Credentials, error) {
	value := string(raw)
	if strings.HasSuffix(value, "\n") {
		value = strings.TrimSuffix(value, "\n")
	}
	if strings.Count(value, ":") != 1 {
		return Credentials{}, errors.New("Pushover credentials must contain one user:token separator")
	}
	parts := strings.SplitN(value, ":", 2)
	credentials := Credentials{User: parts[0], Token: parts[1]}
	if err := credentials.Validate(); err != nil {
		return Credentials{}, err
	}
	return credentials, nil
}

func (c Credentials) Validate() error {
	if !validKey(c.User) || !validKey(c.Token) {
		return errors.New("Pushover user and API token must each be 30 ASCII alphanumeric characters")
	}
	return nil
}

func validKey(value string) bool {
	if len(value) != keyLength {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

type Client struct {
	HTTP           *http.Client
	validateURL    string
	messageURL     string
	requestTimeout time.Duration
}

func NewClient(httpClient *http.Client) Client {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	copyClient := *httpClient
	if copyClient.Timeout == 0 {
		copyClient.Timeout = 15 * time.Second
	}
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return Client{HTTP: &copyClient, validateURL: validateEndpoint, messageURL: messageEndpoint, requestTimeout: 15 * time.Second}
}

func (c Client) Validate(ctx context.Context, credentials Credentials) error {
	if err := credentials.Validate(); err != nil {
		return err
	}
	_, err := c.post(ctx, c.validateURL, credentials, nil)
	return err
}

func (c Client) Send(ctx context.Context, credentials Credentials, title, message string, priority int) error {
	if err := credentials.Validate(); err != nil {
		return err
	}
	if message == "" || !utf8.ValidString(title) || !utf8.ValidString(message) || utf8.RuneCountInString(title) > maxTitleChars || utf8.RuneCountInString(message) > maxMessageChars || strings.ContainsAny(title+message, "\x00\r\n") {
		return errors.New("Pushover message is empty or invalid")
	}
	if priority == 2 || priority < -2 || priority > 1 {
		return errors.New("Pushover priority must be between -2 and 1")
	}
	form := url.Values{"title": {title}, "message": {message}, "priority": {fmt.Sprint(priority)}}
	_, err := c.post(ctx, c.messageURL, credentials, form)
	return err
}

func (c Client) post(ctx context.Context, endpoint string, credentials Credentials, extra url.Values) (int, error) {
	if c.HTTP == nil || endpoint == "" {
		return 0, errors.New("Pushover HTTP client is unavailable")
	}
	form := url.Values{"user": {credentials.User}, "token": {credentials.Token}}
	for key, values := range extra {
		for _, value := range values {
			form.Add(key, value)
		}
	}
	requestCtx := ctx
	if c.requestTimeout > 0 {
		var cancel context.CancelFunc
		requestCtx, cancel = context.WithTimeout(ctx, c.requestTimeout)
		defer cancel()
	}
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, errors.New("Pushover request could not be created")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.HTTP.Do(request)
	if err != nil {
		return 0, errors.New("Pushover request failed")
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil || len(body) > maxResponseBytes {
		return response.StatusCode, errors.New("Pushover response exceeded its bound")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, fmt.Errorf("Pushover request returned HTTP %d", response.StatusCode)
	}
	var result struct {
		Status int `json:"status"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(body), &result); err != nil || result.Status != 1 {
		return response.StatusCode, errors.New("Pushover response reported failure")
	}
	return response.StatusCode, nil
}
