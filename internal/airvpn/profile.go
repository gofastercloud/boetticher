// Package airvpn handles the controller-side AirVPN profile flow. It exposes
// only public endpoint metadata to routing callers.
package airvpn

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/telemetry"
)

const (
	DefaultAPIBaseURL = "https://airvpn.org/api"
	DefaultPort       = 1637
	DefaultKeepalive  = 25
	maxProfileBytes   = 128 * 1024
	maxStatusBytes    = 2 * 1024 * 1024
	generatorTimeout  = 30 * time.Second
)

// Profile is the validated and normalized WireGuard profile. Config is
// secret material and must only be passed to encrypted-secret and credential
// installation paths.
type Profile struct {
	Config   string
	Metadata Metadata
}

// Metadata contains only values safe for firewall and routing projections.
type Metadata struct {
	EndpointHost  string `json:"endpoint_host"`
	EndpointPort  int    `json:"endpoint_port"`
	TunnelAddress string `json:"tunnel_address"`
	SHA256        string `json:"sha256"`
}

// Client calls the AirVPN configuration generator. BaseURL is injectable for
// tests and defaults to the provider API.
type Client struct {
	HTTPClient *http.Client
	BaseURL    string
}

func (c Client) Generate(ctx context.Context, apiKey, servers string) (profile Profile, err error) {
	if strings.TrimSpace(apiKey) == "" || strings.ContainsAny(apiKey, " \t\r\n") {
		return Profile{}, errors.New("AirVPN API key is empty or contains whitespace")
	}
	if err := validateSelector(servers); err != nil {
		return Profile{}, err
	}
	baseURL := c.BaseURL
	if baseURL == "" {
		baseURL = DefaultAPIBaseURL
	}
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/") + "/generator/")
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return Profile{}, errors.New("AirVPN generator URL must be HTTPS without user information")
	}
	query := parsed.Query()
	query.Set("protocols", fmt.Sprintf("wireguard_1_udp_%d", DefaultPort))
	query.Set("servers", servers)
	query.Set("device", "default")
	query.Set("resolve", "on")
	query.Set("iplayer_entry", "ipv4")
	parsed.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return Profile{}, fmt.Errorf("create AirVPN generator request: %w", err)
	}
	request.Header.Set("Api-Key", apiKey)
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: generatorTimeout}
	} else {
		// Do not let an injected client remove the generator's bounded request
		// lifetime. Preserve a shorter caller-specific timeout.
		clientCopy := *httpClient
		if clientCopy.Timeout <= 0 || clientCopy.Timeout > generatorTimeout {
			clientCopy.Timeout = generatorTimeout
		}
		httpClient = &clientCopy
	}
	if httpClient.CheckRedirect == nil {
		httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	requestStarted := time.Now()
	status := 0
	defer func() {
		telemetry.Record(ctx, telemetry.Event{
			Category: "provider_api", Operation: "generate_profile", Target: "airvpn-generator",
			Method: http.MethodGet, Status: status, Duration: time.Since(requestStarted), Success: err == nil,
		})
	}()
	response, err := httpClient.Do(request)
	if err != nil {
		return Profile{}, fmt.Errorf("request AirVPN WireGuard profile: %w", err)
	}
	defer response.Body.Close()
	status = response.StatusCode
	data, err := io.ReadAll(io.LimitReader(response.Body, maxProfileBytes+1))
	if err != nil {
		return Profile{}, fmt.Errorf("read AirVPN WireGuard profile: %w", err)
	}
	if len(data) > maxProfileBytes {
		return Profile{}, errors.New("AirVPN WireGuard profile exceeds the safe size limit")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Profile{}, fmt.Errorf("AirVPN generator returned HTTP %d", response.StatusCode)
	}
	profile, err = ParseProfile(data)
	if err != nil {
		if providerResponseShape(data) == "json-provider-error" {
			available, statusErr := c.selectorHasLiveServer(ctx, baseURL, servers, httpClient)
			if statusErr == nil && !available {
				return Profile{}, fmt.Errorf("AirVPN selector %q currently has no live provider servers; choose a current AirVPN server, country, or continent", servers)
			}
		}
		return Profile{}, fmt.Errorf("AirVPN generator returned an invalid WireGuard profile (%s): %w", providerResponseSummary(response.Header.Get("Content-Type"), data), err)
	}
	return profile, nil
}

type providerStatus struct {
	Servers []providerServer `json:"servers"`
}

type providerServer struct {
	PublicName  string `json:"public_name"`
	CountryName string `json:"country_name"`
	CountryCode string `json:"country_code"`
	Continent   string `json:"continent"`
	Health      string `json:"health"`
}

// selectorHasLiveServer checks the public provider status only after a JSON
// generator error, so an unavailable selector gets a concrete remediation
// without adding an API call to the successful profile path.
func (c Client) selectorHasLiveServer(ctx context.Context, baseURL, selector string, httpClient *http.Client) (available bool, err error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/") + "/status/")
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return false, errors.New("AirVPN status URL must be HTTPS without user information")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return false, fmt.Errorf("create AirVPN status request: %w", err)
	}
	requestStarted := time.Now()
	status := 0
	defer func() {
		telemetry.Record(ctx, telemetry.Event{
			Category: "provider_api", Operation: "selector_status", Target: "airvpn-status",
			Method: http.MethodGet, Status: status, Duration: time.Since(requestStarted), Success: err == nil,
		})
	}()
	response, err := httpClient.Do(request)
	if err != nil {
		return false, fmt.Errorf("request AirVPN status: %w", err)
	}
	defer response.Body.Close()
	status = response.StatusCode
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return false, fmt.Errorf("AirVPN status returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxStatusBytes+1))
	if err != nil {
		return false, fmt.Errorf("read AirVPN status: %w", err)
	}
	if len(data) > maxStatusBytes {
		return false, errors.New("AirVPN status exceeds the safe size limit")
	}
	var provider providerStatus
	if err := json.Unmarshal(data, &provider); err != nil {
		return false, errors.New("parse AirVPN status")
	}
	needle := strings.ToLower(strings.TrimSpace(selector))
	for _, server := range provider.Servers {
		if strings.ToLower(strings.TrimSpace(server.Health)) != "ok" {
			continue
		}
		if needle == "earth" || needle == "all" || selectorMatchesServer(needle, server) {
			return true, nil
		}
	}
	return false, nil
}

func selectorMatchesServer(selector string, server providerServer) bool {
	for _, candidate := range []string{server.PublicName, server.CountryName, server.CountryCode, server.Continent} {
		if selector == strings.ToLower(strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

// providerResponseSummary exposes only the small diagnostics needed to
// distinguish an API error document from malformed WireGuard output. It must
// never include response content because a provider profile contains keys.
func providerResponseSummary(contentType string, data []byte) string {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType == "" {
		mediaType = "unspecified"
	}
	return fmt.Sprintf("content_type=%s bytes=%d shape=%s", mediaType, len(data), providerResponseShape(data))
}

func providerResponseShape(data []byte) string {
	profileText := strings.TrimPrefix(strings.ReplaceAll(string(data), "\r\n", "\n"), "\ufeff")
	for _, raw := range strings.Split(profileText, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "[Interface]"):
			return "wireguard"
		case strings.HasPrefix(line, "<"):
			return "markup"
		case strings.HasPrefix(line, "{") || strings.HasPrefix(line, "["):
			return "json-" + providerJSONErrorCategory(data)
		default:
			return "plain"
		}
	}
	return "empty"
}

func providerJSONErrorCategory(data []byte) string {
	var response any
	if err := json.Unmarshal(data, &response); err != nil {
		return "invalid"
	}
	var details []string
	collectProviderJSONStrings(response, &details, 0)
	message := strings.ToLower(strings.Join(details, " "))
	switch {
	case strings.Contains(message, "device") || strings.Contains(message, "user key"):
		return "device"
	case strings.Contains(message, "api") && strings.Contains(message, "key"),
		strings.Contains(message, "invalid key") || strings.Contains(message, "expired key") || strings.Contains(message, "missing key") || strings.Contains(message, "key required") || strings.Contains(message, "key is required"):
		return "api-key"
	case strings.Contains(message, "authoriz") || strings.Contains(message, "authenticat"):
		return "authorization"
	case strings.Contains(message, "parameter") || strings.Contains(message, "argument") || strings.Contains(message, "option") || strings.Contains(message, "protocol") || strings.Contains(message, "format"):
		return "request"
	case strings.Contains(message, "server") || strings.Contains(message, "country") || strings.Contains(message, "region"):
		return "server-selector"
	case strings.Contains(message, "subscription") || strings.Contains(message, "account") || strings.Contains(message, "plan") || strings.Contains(message, "credit") || strings.Contains(message, "active access") || strings.Contains(message, "active service"):
		return "account"
	case message == "":
		return "unspecified"
	default:
		return "provider-error"
	}
}

func collectProviderJSONStrings(value any, details *[]string, depth int) {
	if depth > 8 || len(*details) >= 32 {
		return
	}
	switch typed := value.(type) {
	case string:
		*details = append(*details, typed)
	case []any:
		for _, child := range typed {
			collectProviderJSONStrings(child, details, depth+1)
		}
	case map[string]any:
		for _, child := range typed {
			collectProviderJSONStrings(child, details, depth+1)
		}
	}
}

func ParseProfile(data []byte) (Profile, error) {
	if len(data) == 0 || len(data) > maxProfileBytes {
		return Profile{}, errors.New("AirVPN WireGuard profile is empty or too large")
	}
	sections := map[string]map[string]string{}
	section := ""
	profileText := strings.TrimPrefix(strings.ReplaceAll(string(data), "\r\n", "\n"), "\ufeff")
	for lineNumber, raw := range strings.Split(profileText, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section != "Interface" && section != "Peer" {
				return Profile{}, fmt.Errorf("AirVPN profile line %d uses an unsupported section", lineNumber+1)
			}
			if _, exists := sections[section]; exists {
				return Profile{}, fmt.Errorf("AirVPN profile contains duplicate %s section", section)
			}
			sections[section] = map[string]string{}
			continue
		}
		if section == "" {
			return Profile{}, fmt.Errorf("AirVPN profile line %d appears before a section", lineNumber+1)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return Profile{}, fmt.Errorf("AirVPN profile line %d is not a key/value entry", lineNumber+1)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if value == "" || strings.ContainsRune(value, '\x00') {
			return Profile{}, fmt.Errorf("AirVPN profile line %d has an empty or invalid value", lineNumber+1)
		}
		if _, exists := sections[section][key]; exists {
			return Profile{}, fmt.Errorf("AirVPN profile contains duplicate %s key", key)
		}
		if !supportedKey(section, key) {
			return Profile{}, fmt.Errorf("AirVPN profile contains unsupported %s key", key)
		}
		sections[section][key] = value
	}
	iface, ifaceOK := sections["Interface"]
	peer, peerOK := sections["Peer"]
	if !ifaceOK || !peerOK {
		return Profile{}, errors.New("AirVPN profile requires exactly one Interface and one Peer section")
	}
	for _, key := range []string{"PrivateKey", "Address"} {
		if iface[key] == "" {
			return Profile{}, fmt.Errorf("AirVPN profile is missing Interface.%s", key)
		}
	}
	if err := validateKey(iface["PrivateKey"]); err != nil {
		return Profile{}, fmt.Errorf("AirVPN private key: %w", err)
	}
	addresses, tunnelAddress, err := validateAddresses(iface["Address"])
	if err != nil {
		return Profile{}, err
	}
	for _, key := range []string{"PublicKey", "PresharedKey", "Endpoint", "AllowedIPs"} {
		if peer[key] == "" {
			return Profile{}, fmt.Errorf("AirVPN profile is missing Peer.%s", key)
		}
	}
	if err := validateKey(peer["PublicKey"]); err != nil {
		return Profile{}, fmt.Errorf("AirVPN peer public key: %w", err)
	}
	if err := validateKey(peer["PresharedKey"]); err != nil {
		return Profile{}, fmt.Errorf("AirVPN peer preshared key: %w", err)
	}
	endpointHost, endpointPort, err := validateEndpoint(peer["Endpoint"])
	if err != nil {
		return Profile{}, err
	}
	foundDefault := false
	for _, allowed := range strings.Split(peer["AllowedIPs"], ",") {
		allowed = strings.TrimSpace(allowed)
		if strings.Contains(allowed, ":") {
			return Profile{}, errors.New("AirVPN profile must be IPv4-only")
		}
		if allowed != "0.0.0.0/0" {
			return Profile{}, errors.New("AirVPN profile must use only AllowedIPs=0.0.0.0/0")
		}
		if foundDefault {
			return Profile{}, errors.New("AirVPN profile contains duplicate AllowedIPs")
		}
		foundDefault = true
	}
	if !foundDefault {
		return Profile{}, errors.New("AirVPN profile must contain AllowedIPs=0.0.0.0/0")
	}
	keepalive := DefaultKeepalive
	if value := peer["PersistentKeepalive"]; value != "" {
		keepalive, err = strconv.Atoi(value)
		if err != nil || keepalive < 0 || keepalive > 120 {
			return Profile{}, errors.New("AirVPN profile has an invalid PersistentKeepalive")
		}
	}
	mtu := 1320
	if value := iface["MTU"]; value != "" {
		mtu, err = strconv.Atoi(value)
		if err != nil || mtu < 576 || mtu > 9000 {
			return Profile{}, errors.New("AirVPN profile has an invalid MTU")
		}
	}
	normalized := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nMTU = %d\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = %s:%d\nPersistentKeepalive = %d\n", iface["PrivateKey"], strings.Join(addresses, ", "), mtu, peer["PublicKey"], peer["PresharedKey"], endpointHost, endpointPort, keepalive)
	digest := sha256.Sum256([]byte(normalized))
	return Profile{Config: normalized, Metadata: Metadata{EndpointHost: endpointHost, EndpointPort: endpointPort, TunnelAddress: tunnelAddress, SHA256: hex.EncodeToString(digest[:])}}, nil
}

func supportedKey(section, key string) bool {
	if section == "Interface" {
		return key == "PrivateKey" || key == "Address" || key == "DNS" || key == "MTU"
	}
	return key == "PublicKey" || key == "PresharedKey" || key == "Endpoint" || key == "AllowedIPs" || key == "PersistentKeepalive"
}

func validateSelector(selector string) error {
	if selector == "" || len(selector) > 128 {
		return errors.New("AirVPN servers selector is required and must be at most 128 characters")
	}
	for _, r := range selector {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return errors.New("AirVPN servers selector contains unsafe characters")
		}
	}
	return nil
}

func validateKey(value string) error {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return errors.New("must be a base64-encoded 32-byte WireGuard key")
	}
	return nil
}

func validateAddresses(value string) ([]string, string, error) {
	parts := strings.Split(value, ",")
	addresses := make([]string, 0, len(parts))
	first := ""
	for _, part := range parts {
		part = strings.TrimSpace(part)
		ip, _, err := net.ParseCIDR(part)
		if err != nil || ip.To4() == nil {
			return nil, "", errors.New("AirVPN profile must contain IPv4 interface addresses")
		}
		if first == "" {
			first = part
		}
		addresses = append(addresses, part)
	}
	if len(addresses) == 0 {
		return nil, "", errors.New("AirVPN profile has no interface address")
	}
	return addresses, first, nil
}

func validateEndpoint(value string) (string, int, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return "", 0, errors.New("AirVPN profile has an invalid provider endpoint")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port != DefaultPort {
		return "", 0, fmt.Errorf("AirVPN profile must use provider endpoint port %d", DefaultPort)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return "", 0, errors.New("AirVPN provider endpoint must be IPv4")
		}
		return ip.String(), port, nil
	}
	if strings.ContainsAny(host, " \t\r\n/\\") || len(host) > 253 {
		return "", 0, errors.New("AirVPN provider endpoint hostname is invalid")
	}
	return host, port, nil
}
