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
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
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

func (c *Client) Delete(ctx context.Context, endpoint string) error {
	return c.request(ctx, http.MethodDelete, endpoint, nil, nil, nil)
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

type GuestAgentAddress struct {
	IPAddress string `json:"ip-address"`
	IPType    string `json:"ip-address-type"`
}

type GuestAgentInterface struct {
	Name            string              `json:"name"`
	HardwareAddress string              `json:"hardware-address"`
	IPAddresses     []GuestAgentAddress `json:"ip-addresses"`
}

type StorageContent struct {
	VolID    string `json:"volid"`
	Filename string `json:"filename"`
	Checksum string `json:"checksum"`
	CSum     string `json:"csum"`
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

func (c *Client) ImportDisk(ctx context.Context, node string, vmid int, source, storage, format string) (string, error) {
	if node == "" || vmid <= 0 || source == "" || storage == "" {
		return "", errors.New("node, positive VMID, source, and storage are required")
	}
	var upid string
	form := url.Values{"source": {source}, "storage": {storage}}
	if format != "" {
		form.Set("format", format)
	}
	if err := c.Post(ctx, path.Join("/nodes", node, "qemu", strconv.Itoa(vmid), "importdisk"), form, &upid); err != nil {
		return "", fmt.Errorf("import gateway disk: %w", err)
	}
	if upid == "" {
		return "", errors.New("Proxmox did not return a disk import task")
	}
	return upid, nil
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

// QEMUAgentNetworkInterfaces reads only guest-agent network evidence. It is
// used to discover the temporary DHCP-backed builder address; no operator or
// module identity is inferred from a hostname or arbitrary user address.
func (c *Client) QEMUAgentNetworkInterfaces(ctx context.Context, node string, vmid int) ([]GuestAgentInterface, error) {
	if node == "" || vmid <= 0 {
		return nil, errors.New("node and positive VMID are required")
	}
	var interfaces []GuestAgentInterface
	if err := c.Get(ctx, path.Join("/nodes", node, "qemu", strconv.Itoa(vmid), "agent", "network-get-interfaces"), nil, &interfaces); err != nil {
		return nil, fmt.Errorf("read QEMU guest-agent network interfaces: %w", err)
	}
	return interfaces, nil
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

func (c *Client) StorageContent(ctx context.Context, node, storage, content string) ([]StorageContent, error) {
	if node == "" || storage == "" {
		return nil, errors.New("Proxmox node and storage are required")
	}
	var result []StorageContent
	query := url.Values{}
	if content != "" {
		query.Set("content", content)
	}
	if err := c.Get(ctx, path.Join("/nodes", node, "storage", storage, "content"), query, &result); err != nil {
		return nil, fmt.Errorf("list Proxmox storage content: %w", err)
	}
	return result, nil
}

// UploadStorageFile imports one already-qualified appliance byte stream into
// a named Proxmox storage content class. The caller must verify its content
// digest before calling this method.
func (c *Client) UploadStorageFile(ctx context.Context, node, storage, content, source, filename string) error {
	if node == "" || storage == "" || content == "" || source == "" || filename == "" {
		return errors.New("node, storage, content, source, and filename are required")
	}
	if strings.ContainsAny(filename, "/\\\r\n") {
		return errors.New("uploaded filename must be a plain filename")
	}
	file, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open qualified artifact %s: %w", source, err)
	}
	defer file.Close()
	body := &bytes.Buffer{}
	multipartWriter := multipart.NewWriter(body)
	if err := multipartWriter.WriteField("content", content); err != nil {
		return err
	}
	part, err := multipartWriter.CreateFormFile("filename", filename)
	if err != nil {
		return err
	}
	if _, err := io.Copy(part, file); err != nil {
		return fmt.Errorf("read qualified artifact %s: %w", source, err)
	}
	if err := multipartWriter.Close(); err != nil {
		return err
	}
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return err
	}
	base.Path = path.Join(base.Path, "/nodes", node, "storage", storage, "upload")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), body)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	if c.Token != "" {
		request.Header.Set("Authorization", c.Token)
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
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &APIError{StatusCode: response.StatusCode, Status: response.Status, Message: strings.TrimSpace(string(data))}
	}
	return nil
}

// UploadStorageText uploads deterministic non-secret cloud-init content to a
// snippets storage class without creating a controller-side plaintext file.
func (c *Client) UploadStorageText(ctx context.Context, node, storage, content, filename, value string) error {
	if node == "" || storage == "" || content == "" || filename == "" {
		return errors.New("node, storage, content, and filename are required")
	}
	if strings.ContainsAny(filename, "/\\\r\n") {
		return errors.New("uploaded filename must be a plain filename")
	}
	body := &bytes.Buffer{}
	multipartWriter := multipart.NewWriter(body)
	if err := multipartWriter.WriteField("content", content); err != nil {
		return err
	}
	part, err := multipartWriter.CreateFormFile("filename", filename)
	if err != nil {
		return err
	}
	if _, err := part.Write([]byte(value)); err != nil {
		return err
	}
	if err := multipartWriter.Close(); err != nil {
		return err
	}
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return err
	}
	base.Path = path.Join(base.Path, "/nodes", node, "storage", storage, "upload")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), body)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	if c.Token != "" {
		request.Header.Set("Authorization", c.Token)
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
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &APIError{StatusCode: response.StatusCode, Status: response.Status, Message: strings.TrimSpace(string(data))}
	}
	return nil
}

// DownloadURL asks Proxmox to download a pinned image and verify it before
// making it available in storage. The checksum is sent as an API form field,
// never placed in a shell command or a generated public artifact.
func (c *Client) DownloadURL(ctx context.Context, node, storage, filename, imageURL, checksum string) (string, error) {
	if node == "" || storage == "" || filename == "" || imageURL == "" || checksum == "" {
		return "", errors.New("node, storage, filename, image URL, and checksum are required")
	}
	parsed, err := url.Parse(imageURL)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return "", errors.New("gateway image URL must be an HTTP(S) URL")
	}
	if strings.ContainsAny(filename, "/\\\r\n") || len(checksum) != 128 || !isHex(checksum) {
		return "", errors.New("gateway image filename or SHA-512 checksum is invalid")
	}
	var upid string
	if err := c.Post(ctx, path.Join("/nodes", node, "storage", storage, "download-url"), url.Values{
		"content":            {"iso"},
		"filename":           {filename},
		"url":                {imageURL},
		"checksum":           {checksum},
		"checksum-algorithm": {"sha512"},
	}, &upid); err != nil {
		return "", fmt.Errorf("download gateway image: %w", err)
	}
	if upid == "" {
		return "", errors.New("Proxmox did not return a gateway image download task")
	}
	return upid, nil
}

func (c *Client) WaitTask(ctx context.Context, node, upid string) error {
	if node == "" || upid == "" {
		return errors.New("Proxmox task node and UPID are required")
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		var status struct {
			Status     string `json:"status"`
			ExitStatus string `json:"exitstatus"`
		}
		if err := c.Get(ctx, path.Join("/nodes", node, "tasks", upid, "status"), nil, &status); err != nil {
			return fmt.Errorf("inspect Proxmox task: %w", err)
		}
		if status.Status == "stopped" {
			if status.ExitStatus != "OK" && status.ExitStatus != "" {
				return fmt.Errorf("Proxmox task failed: %s", status.ExitStatus)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *Client) EnsureCloudImage(ctx context.Context, node, storage, filename, imageURL, checksum string) (string, error) {
	contents, err := c.StorageContent(ctx, node, storage, "iso")
	if err != nil {
		return "", err
	}
	for _, content := range contents {
		if path.Base(content.Filename) != filename && !strings.HasSuffix(content.VolID, "/"+filename) {
			continue
		}
		observed := content.Checksum
		if observed == "" {
			observed = content.CSum
		}
		if observed != "" && !strings.EqualFold(observed, checksum) {
			return "", fmt.Errorf("existing gateway image %q has a different checksum", filename)
		}
		return content.VolID, nil
	}
	upid, err := c.DownloadURL(ctx, node, storage, filename, imageURL, checksum)
	if err != nil {
		return "", err
	}
	if err := c.WaitTask(ctx, node, upid); err != nil {
		return "", err
	}
	contents, err = c.StorageContent(ctx, node, storage, "iso")
	if err != nil {
		return "", err
	}
	for _, content := range contents {
		if path.Base(content.Filename) == filename || strings.HasSuffix(content.VolID, "/"+filename) {
			return content.VolID, nil
		}
	}
	return "", fmt.Errorf("downloaded gateway image %q was not found in Proxmox storage", filename)
}

func isHex(value string) bool {
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

// EnsureDirectoryStorage registers the fixed backup directory used by the
// dedicated-data-disk profile. It refuses to accept a conflicting existing
// definition and relies on Proxmox to reject a missing/unmounted path.
func (c *Client) EnsureDirectoryStorage(ctx context.Context, storageID, storagePath string) error {
	return c.EnsureDirectoryStorageContent(ctx, storageID, storagePath, []string{"backup"})
}

// EnsureDirectoryStorageContent validates a named directory storage and adds
// only the requested content types. It never changes the path or adopts a
// different storage with the same name.
func (c *Client) EnsureDirectoryStorageContent(ctx context.Context, storageID, storagePath string, requiredContent []string) error {
	if c == nil {
		return errors.New("Proxmox client is required")
	}
	if storageID == "" || storagePath == "" || len(requiredContent) == 0 {
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
		if storage.Type != "dir" || storage.Path != storagePath {
			return fmt.Errorf("Proxmox storage %q has a conflicting definition", storageID)
		}
		content := splitContent(storage.Content)
		missing := false
		for _, wanted := range requiredContent {
			if !content[wanted] {
				content[wanted] = true
				missing = true
			}
		}
		if missing {
			values := make([]string, 0, len(content))
			for value := range content {
				values = append(values, value)
			}
			sort.Strings(values)
			if err := c.Put(ctx, path.Join("/cluster/storage", storageID), url.Values{"content": {strings.Join(values, ",")}}, nil); err != nil {
				return fmt.Errorf("extend Proxmox storage %q content: %w", storageID, err)
			}
		}
		return nil
	}
	if err := c.Post(ctx, "/cluster/storage", url.Values{
		"storage": {storageID},
		"type":    {"dir"},
		"path":    {storagePath},
		"content": {strings.Join(requiredContent, ",")},
	}, nil); err != nil {
		return fmt.Errorf("create Proxmox directory storage %q: %w", storageID, err)
	}
	return nil
}

func splitContent(value string) map[string]bool {
	result := make(map[string]bool)
	for _, item := range strings.Split(value, ",") {
		if item != "" {
			result[item] = true
		}
	}
	return result
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
