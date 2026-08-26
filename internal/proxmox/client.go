package proxmox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

type Config struct {
	BaseURL     string
	User        string
	TokenID     string
	TokenSecret string
	CAFile      string
	Insecure    bool
	Timeout     time.Duration
}

type APIError struct {
	StatusCode int
	Status     string
	Message    string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("Proxmox API: %s", e.Status)
	}
	return fmt.Sprintf("Proxmox API: %s: %s", e.Status, e.Message)
}

func NewClient(config Config) (*Client, error) {
	if config.BaseURL == "" {
		return nil, errors.New("Proxmox API base URL is required")
	}
	parsed, err := url.Parse(strings.TrimRight(config.BaseURL, "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("Proxmox API base URL must be an https URL")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: config.Insecure} // #nosec G402 -- only enabled by explicit operator choice.
	if config.CAFile != "" {
		data, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read Proxmox CA file: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("Proxmox CA file contains no certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	token := ""
	if config.User != "" && config.TokenID != "" {
		token = "PVEAPIToken=" + config.User + "!" + config.TokenID + "=" + config.TokenSecret
	}
	return &Client{BaseURL: strings.TrimRight(config.BaseURL, "/"), Token: token, HTTP: &http.Client{Transport: transport, Timeout: timeout}}, nil
}

func (c *Client) Get(ctx context.Context, endpoint string, query url.Values, out any) error {
	return c.request(ctx, http.MethodGet, endpoint, query, nil, out)
}

func (c *Client) Post(ctx context.Context, endpoint string, form url.Values, out any) error {
	return c.request(ctx, http.MethodPost, endpoint, nil, form, out)
}

func (c *Client) Put(ctx context.Context, endpoint string, form url.Values, out any) error {
	return c.request(ctx, http.MethodPut, endpoint, nil, form, out)
}

func (c *Client) Version(ctx context.Context) (string, error) {
	var result struct {
		Version string `json:"version"`
		Release string `json:"release"`
	}
	if err := c.Get(ctx, "/version", nil, &result); err != nil {
		return "", err
	}
	if result.Version == "" {
		return result.Release, nil
	}
	return result.Version, nil
}

func (c *Client) Nodes(ctx context.Context) ([]Node, error) {
	var nodes []Node
	if err := c.Get(ctx, "/cluster/resources", nil, &nodes); err != nil {
		return nil, err
	}
	return nodes, nil
}

type Node struct {
	Node   string `json:"node"`
	Status string `json:"status"`
	Type   string `json:"type"`
}

func (c *Client) CreateUser(ctx context.Context, userID, comment string) error {
	return c.Post(ctx, "/access/users", url.Values{"userid": {userID}, "comment": {comment}}, nil)
}

func (c *Client) CreateToken(ctx context.Context, userID, tokenID string) (string, error) {
	var result struct {
		Value string `json:"value"`
	}
	endpoint := path.Join("/access/users", userID, "token", tokenID)
	if err := c.Post(ctx, endpoint, url.Values{"privsep": {"1"}}, &result); err != nil {
		return "", err
	}
	if result.Value == "" {
		return "", errors.New("Proxmox did not return an API token secret")
	}
	return result.Value, nil
}

func (c *Client) SetACL(ctx context.Context, resource, users, role string) error {
	return c.Post(ctx, "/access/acl", url.Values{"path": {resource}, "users": {users}, "role": {role}, "propagate": {"1"}}, nil)
}

func (c *Client) CreateVM(ctx context.Context, node string, vmid int, params url.Values) error {
	if vmid <= 0 || node == "" {
		return errors.New("Proxmox node and positive VMID are required")
	}
	if params == nil {
		params = url.Values{}
	}
	params.Set("vmid", strconv.Itoa(vmid))
	return c.Post(ctx, path.Join("/nodes", node, "qemu"), params, nil)
}

func (c *Client) SetVMConfig(ctx context.Context, node string, vmid int, params url.Values) error {
	if vmid <= 0 || node == "" {
		return errors.New("Proxmox node and positive VMID are required")
	}
	return c.Post(ctx, path.Join("/nodes", node, "qemu", strconv.Itoa(vmid), "config"), params, nil)
}

func (c *Client) StartVM(ctx context.Context, node string, vmid int) error {
	return c.Post(ctx, path.Join("/nodes", node, "qemu", strconv.Itoa(vmid), "status", "start"), nil, nil)
}

func (c *Client) CreateLXC(ctx context.Context, node string, vmid int, params url.Values) error {
	if vmid <= 0 || node == "" {
		return errors.New("Proxmox node and positive VMID are required")
	}
	if params == nil {
		params = url.Values{}
	}
	params.Set("vmid", strconv.Itoa(vmid))
	return c.Post(ctx, path.Join("/nodes", node, "lxc"), params, nil)
}

func (c *Client) SetLXCConfig(ctx context.Context, node string, vmid int, params url.Values) error {
	if vmid <= 0 || node == "" {
		return errors.New("Proxmox node and positive VMID are required")
	}
	return c.Post(ctx, path.Join("/nodes", node, "lxc", strconv.Itoa(vmid), "config"), params, nil)
}

func (c *Client) StartLXC(ctx context.Context, node string, vmid int) error {
	return c.Post(ctx, path.Join("/nodes", node, "lxc", strconv.Itoa(vmid), "status", "start"), nil, nil)
}

func (c *Client) QEMUConfig(ctx context.Context, node string, vmid int, out any) error {
	return c.Get(ctx, path.Join("/nodes", node, "qemu", strconv.Itoa(vmid), "config"), nil, out)
}

func (c *Client) LXCConfig(ctx context.Context, node string, vmid int, out any) error {
	return c.Get(ctx, path.Join("/nodes", node, "lxc", strconv.Itoa(vmid), "config"), nil, out)
}

func (c *Client) ListVMs(ctx context.Context, node string) ([]GuestSummary, error) {
	var guests []GuestSummary
	if err := c.Get(ctx, path.Join("/nodes", node, "qemu"), nil, &guests); err != nil {
		return nil, err
	}
	for i := range guests {
		guests[i].Kind = KindQEMU
	}
	return guests, nil
}

func (c *Client) ListLXCs(ctx context.Context, node string) ([]GuestSummary, error) {
	var guests []GuestSummary
	if err := c.Get(ctx, path.Join("/nodes", node, "lxc"), nil, &guests); err != nil {
		return nil, err
	}
	for i := range guests {
		guests[i].Kind = KindLXC
	}
	return guests, nil
}

func (c *Client) NodeNetwork(ctx context.Context, node string, out any) error {
	return c.Get(ctx, path.Join("/nodes", node, "network"), nil, out)
}

// EnsureDirectoryStorage registers the fixed backup directory used by the
// dedicated-data-disk profile. It refuses to accept a conflicting existing
// definition and relies on Proxmox to reject a missing/unmounted path.
func (c *Client) EnsureDirectoryStorage(ctx context.Context, storageID, storagePath string) error {
	if c == nil {
		return errors.New("Proxmox client is required")
	}
	if storageID == "" || storagePath == "" {
		return errors.New("storage ID and path are required")
	}
	var storages []struct {
		Storage string `json:"storage"`
		Type    string `json:"type"`
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := c.Get(ctx, "/cluster/storage", nil, &storages); err != nil {
		return fmt.Errorf("list Proxmox storage: %w", err)
	}
	for _, storage := range storages {
		if storage.Storage != storageID {
			continue
		}
		if storage.Type != "dir" || storage.Path != storagePath || !strings.Contains(storage.Content, "backup") {
			return fmt.Errorf("Proxmox storage %q has a conflicting definition", storageID)
		}
		return nil
	}
	if err := c.Post(ctx, "/cluster/storage", url.Values{
		"storage": {storageID},
		"type":    {"dir"},
		"path":    {storagePath},
		"content": {"backup"},
	}, nil); err != nil {
		return fmt.Errorf("create Proxmox backup storage %q: %w", storageID, err)
	}
	return nil
}

// EnsureLVMThinStorage registers the fixed guest-disk storage created by the
// dedicated-data-disk initializer. It refuses a conflicting Proxmox storage
// definition and never discovers or adopts arbitrary user storage.
func (c *Client) EnsureLVMThinStorage(ctx context.Context, storageID, volumeGroup, thinPool string) error {
	if c == nil {
		return errors.New("Proxmox client is required")
	}
	if storageID == "" || volumeGroup == "" || thinPool == "" {
		return errors.New("storage ID, volume group, and thin pool are required")
	}
	var storages []struct {
		Storage     string `json:"storage"`
		Type        string `json:"type"`
		VolumeGroup string `json:"vgname"`
		ThinPool    string `json:"thinpool"`
		Content     string `json:"content"`
	}
	if err := c.Get(ctx, "/cluster/storage", nil, &storages); err != nil {
		return fmt.Errorf("list Proxmox storage: %w", err)
	}
	for _, storage := range storages {
		if storage.Storage != storageID {
			continue
		}
		if storage.Type != "lvmthin" || storage.VolumeGroup != volumeGroup || storage.ThinPool != thinPool || !strings.Contains(storage.Content, "images") || !strings.Contains(storage.Content, "rootdir") {
			return fmt.Errorf("Proxmox storage %q has a conflicting definition", storageID)
		}
		return nil
	}
	if err := c.Post(ctx, "/cluster/storage", url.Values{
		"storage": {storageID}, "type": {"lvmthin"}, "vgname": {volumeGroup}, "thinpool": {thinPool}, "content": {"images,rootdir"},
	}, nil); err != nil {
		return fmt.Errorf("create Proxmox guest storage %q: %w", storageID, err)
	}
	return nil
}

func (c *Client) CreateNodeNetwork(ctx context.Context, node string, params url.Values) error {
	return c.Post(ctx, path.Join("/nodes", node, "network"), params, nil)
}

func (c *Client) UpdateNodeNetwork(ctx context.Context, node, iface string, params url.Values) error {
	return c.Put(ctx, path.Join("/nodes", node, "network", iface), params, nil)
}

func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

func (c *Client) request(ctx context.Context, method, endpoint string, query url.Values, form url.Values, out any) error {
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return err
	}
	base.Path = path.Join(base.Path, endpoint)
	if query != nil {
		base.RawQuery = query.Encode()
	}
	var body io.Reader
	if form != nil {
		body = bytes.NewBufferString(form.Encode())
	}
	request, err := http.NewRequestWithContext(ctx, method, base.String(), body)
	if err != nil {
		return err
	}
	if c.Token != "" {
		request.Header.Set("Authorization", c.Token)
	}
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := c.HTTP.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return err
	}
	var envelope struct {
		Data    json.RawMessage `json:"data"`
		Errors  map[string]any  `json:"errors"`
		Message string          `json:"message"`
	}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &envelope)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := envelope.Message
		if message == "" {
			message = strings.TrimSpace(string(data))
		}
		return &APIError{StatusCode: response.StatusCode, Status: response.Status, Message: message}
	}
	if out != nil && len(envelope.Data) > 0 && string(envelope.Data) != "null" {
		if err := json.Unmarshal(envelope.Data, out); err != nil {
			return fmt.Errorf("decode Proxmox API response: %w", err)
		}
	}
	return nil
}
