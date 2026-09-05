package proxmox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/telemetry"
)

type Client struct {
	// RestoreReplacementACL restores the accepted provisioning scope after
	// Proxmox deletes a guest and removes its VMID-specific ACLs.
	RestoreReplacementACL func(context.Context, int) error
	BaseURL               string
	Token                 string
	HTTP                  *http.Client
	snippetRunner         StdinCommandRunner
	snippetAddr           string
	snippetUser           string
}

type Config struct {
	BaseURL     string
	User        string
	TokenID     string
	TokenSecret string
	CAFile      string
	CAPEM       string
	Insecure    bool
	Timeout     time.Duration
	// SnippetRunner is the authenticated Proxmox host path used because PVE
	// 9.2's storage upload API does not accept snippets content.
	SnippetRunner  StdinCommandRunner
	SnippetAddress string
	SnippetUser    string
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
	if parsed.User != nil || net.ParseIP(parsed.Hostname()) == nil || net.ParseIP(parsed.Hostname()).To4() == nil {
		return nil, errors.New("Proxmox API base URL host must be an IPv4 address without credentials")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: config.Insecure} // #nosec G402 -- only enabled by explicit operator choice.
	caPEM := []byte(config.CAPEM)
	caDescription := "Proxmox CA PEM"
	if config.CAFile != "" {
		data, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read Proxmox CA file: %w", err)
		}
		caPEM = data
		caDescription = "Proxmox CA file"
	}
	if len(caPEM) > 0 {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("%s contains no certificates", caDescription)
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
	return &Client{
		BaseURL: strings.TrimRight(config.BaseURL, "/"), Token: token,
		HTTP:          &http.Client{Transport: transport, Timeout: timeout},
		snippetRunner: config.SnippetRunner, snippetAddr: config.SnippetAddress, snippetUser: config.SnippetUser,
	}, nil
}

// SetSnippetRunner installs the already-authorized host path used for the
// small set of Proxmox operations that need host-local snippet access. The
// caller must invoke this only after the exact immutable plan has been
// accepted and temporary Apply authority has been acquired.
func (c *Client) SetSnippetRunner(runner StdinCommandRunner, address, user string) error {
	if c == nil || runner == nil || net.ParseIP(address) == nil || user == "" {
		return errors.New("authorized snippet runner, IPv4 address, and user are required")
	}
	c.snippetRunner = runner
	c.snippetAddr = address
	c.snippetUser = user
	return nil
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

// DestroyQEMU removes a QEMU guest and asks Proxmox to purge related
// configuration and unreferenced disks. Callers must prove ownership before
// invoking this destructive operation; the API client deliberately does not
// infer ownership from a VMID.
func (c *Client) DestroyQEMU(ctx context.Context, node string, vmid int) error {
	return c.destroyQEMU(ctx, node, vmid)
}

func (c *Client) destroyQEMU(ctx context.Context, node string, vmid int) error {
	if node == "" || vmid <= 0 {
		return errors.New("Proxmox node and positive VMID are required")
	}
	var upid string
	if err := c.request(ctx, http.MethodDelete, path.Join("/nodes", node, "qemu", strconv.Itoa(vmid)), url.Values{
		"purge":                      {"1"},
		"destroy-unreferenced-disks": {"1"},
	}, nil, &upid); err != nil {
		return err
	}
	if upid != "" {
		return c.WaitTask(ctx, node, upid)
	}
	return nil
}

// DestroyLXC removes an LXC guest and asks Proxmox to purge its configuration
// and attached unreferenced volumes. Callers must prove the exact guest and
// volume ownership before invoking this destructive operation.
func (c *Client) DestroyLXC(ctx context.Context, node string, vmid int) error {
	if node == "" || vmid <= 0 {
		return errors.New("Proxmox node and positive VMID are required")
	}
	var upid string
	if err := c.request(ctx, http.MethodDelete, path.Join("/nodes", node, "lxc", strconv.Itoa(vmid)), url.Values{
		"purge":                      {"1"},
		"destroy-unreferenced-disks": {"1"},
	}, nil, &upid); err != nil {
		return err
	}
	if upid != "" {
		return c.WaitTask(ctx, node, upid)
	}
	return nil
}

// SetGuestNetworkFilters enables Proxmox guest-level MAC filtering and, for
// statically addressed guests, source-IP filtering. Callers must already have
// proved the guest identity; the API method accepts only a fixed guest kind
// and positive VMID.
func (c *Client) SetGuestNetworkFilters(ctx context.Context, node string, kind GuestKind, vmid int, ipfilter bool) error {
	if node == "" || vmid <= 0 || (kind != KindLXC && kind != KindQEMU) {
		return errors.New("Proxmox node, guest kind, and positive VMID are required")
	}
	endpoint := path.Join("/nodes", node, string(kind), strconv.Itoa(vmid), "firewall", "options")
	ipfilterValue := "0"
	if ipfilter {
		ipfilterValue = "1"
	}
	return c.Put(ctx, endpoint, url.Values{
		"enable":     {"1"},
		"macfilter":  {"1"},
		"ipfilter":   {ipfilterValue},
		"policy_in":  {"ACCEPT"},
		"policy_out": {"ACCEPT"},
	}, nil)
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

// CheckTLS verifies the configured HTTPS transport before bootstrap creates
// credentials. The API may require authentication for the probe, so any HTTP
// response proves the TLS handshake completed; transport and certificate
// failures remain errors.
func (c *Client) CheckTLS(ctx context.Context) (err error) {
	if c == nil || c.HTTP == nil {
		return errors.New("Proxmox client is required")
	}
	started := time.Now()
	status := 0
	defer func() {
		telemetry.Record(ctx, telemetry.Event{
			Category: "proxmox_api", Operation: "/version", Method: http.MethodGet,
			Status: status, Duration: time.Since(started), Success: err == nil || status != 0,
		})
	}()
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return err
	}
	base.Path = path.Join(base.Path, "/version")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return err
	}
	response, err := c.HTTP.Do(request)
	if err != nil {
		return err
	}
	status = response.StatusCode
	return response.Body.Close()
}

func (c *Client) Nodes(ctx context.Context) ([]Node, error) {
	var nodes []Node
	if err := c.Get(ctx, "/nodes", nil, &nodes); err != nil {
		return nil, err
	}
	return nodes, nil
}

// SingleNode resolves the one supported Proxmox node from the authoritative
// node listing. The logical boetticher platform identity is not a Proxmox API
// node binding and must never be used as a fallback here.
func (c *Client) SingleNode(ctx context.Context) (string, error) {
	nodes, err := c.Nodes(ctx)
	if err != nil {
		return "", fmt.Errorf("discover Proxmox nodes: %w", err)
	}
	if len(nodes) == 0 {
		return "", errors.New("HOLD: no Proxmox node discovered")
	}
	if len(nodes) > 1 {
		return "", fmt.Errorf("HOLD: clustered/multi-node Proxmox is unsupported (%d nodes discovered)", len(nodes))
	}
	if !safeNodeID(nodes[0].Node) {
		return "", fmt.Errorf("HOLD: Proxmox node identifier %q is malformed", nodes[0].Node)
	}
	return nodes[0].Node, nil
}

// ResolveSingleNode validates a node listing returned by pvesh or the API.
// It is exported for the pre-token SSH discovery path, which must apply the
// same cardinality and path-safety rules as authenticated API calls.
func ResolveSingleNode(nodes []Node) (string, error) {
	if len(nodes) == 0 {
		return "", errors.New("HOLD: no Proxmox node discovered")
	}
	if len(nodes) > 1 {
		return "", fmt.Errorf("HOLD: clustered/multi-node Proxmox is unsupported (%d nodes discovered)", len(nodes))
	}
	if !safeNodeID(nodes[0].Node) {
		return "", fmt.Errorf("HOLD: Proxmox node identifier %q is malformed", nodes[0].Node)
	}
	return nodes[0].Node, nil
}

func safeNodeID(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !(r == '.' || r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
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

func (c *Client) CreateVM(ctx context.Context, node string, vmid int, params url.Values) error {
	if vmid <= 0 || node == "" {
		return errors.New("Proxmox node and positive VMID are required")
	}
	if params == nil {
		params = url.Values{}
	}
	params.Set("vmid", strconv.Itoa(vmid))
	var upid string
	if err := c.Post(ctx, path.Join("/nodes", node, "qemu"), params, &upid); err != nil {
		return err
	}
	if upid != "" {
		return c.WaitTask(ctx, node, upid)
	}
	return nil
}

func (c *Client) ImportDisk(ctx context.Context, node string, vmid int, source, storage, format string) (string, error) {
	if node == "" || vmid <= 0 || source == "" || storage == "" {
		return "", errors.New("node, positive VMID, source, and storage are required")
	}
	var upid string
	// PVE 9.2 exposes disk import through the QEMU config endpoint. The
	// legacy /importdisk route is a CLI-only operation on that release.
	form := url.Values{"scsi0": {fmt.Sprintf("%s:0,import-from=%s", storage, source)}}
	if format != "" {
		form.Set("scsi0", fmt.Sprintf("%s:0,import-from=%s,format=%s", storage, source, format))
	}
	if err := c.Post(ctx, path.Join("/nodes", node, "qemu", strconv.Itoa(vmid), "config"), form, &upid); err != nil {
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

// MoveQEMUPersistentDisk moves one attached Boetticher persistent SCSI disk
// to the declared storage. The caller must establish ownership from the
// disk's stable serial before invoking this operation. Proxmox deletes the
// source only after its copy task succeeds, which avoids leaving an active
// configuration pointing at a removed source volume.
func (c *Client) MoveQEMUPersistentDisk(ctx context.Context, node string, vmid int, disk, storage, digest string) error {
	if c == nil || !safeNodeID(node) || vmid <= 0 || !safePersistentQEMUDiskKey(disk) || !safeNodeID(storage) || len(digest) != 40 || !isHex(digest) {
		return errors.New("Proxmox node, positive VMID, persistent SCSI disk, storage, and config digest are required")
	}
	var upid string
	if err := c.Post(ctx, path.Join("/nodes", node, "qemu", strconv.Itoa(vmid), "move_disk"), url.Values{
		"disk":    {disk},
		"storage": {storage},
		"digest":  {digest},
		"delete":  {"1"},
	}, &upid); err != nil {
		return fmt.Errorf("move QEMU persistent disk: %w", err)
	}
	if upid == "" {
		return errors.New("Proxmox did not return a QEMU disk move task")
	}
	if err := c.WaitTask(ctx, node, upid); err != nil {
		return fmt.Errorf("wait for QEMU persistent disk move: %w", err)
	}
	return nil
}

func safePersistentQEMUDiskKey(value string) bool {
	if !strings.HasPrefix(value, "scsi") {
		return false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(value, "scsi"))
	return err == nil && index > 0 && index <= 30 && value == "scsi"+strconv.Itoa(index)
}

// MoveLXCPersistentVolume moves one declared LXC mount-point volume to the
// requested storage. Its caller proves the mount point, backup policy, mount
// path, and exact size before this operation is allowed to delete the source.
func (c *Client) MoveLXCPersistentVolume(ctx context.Context, node string, vmid int, volume, storage, digest string) error {
	if c == nil || !safeNodeID(node) || vmid <= 0 || !safePersistentLXCMountpointKey(volume) || !safeNodeID(storage) || len(digest) != 40 || !isHex(digest) {
		return errors.New("Proxmox node, positive VMID, persistent LXC mount point, storage, and config digest are required")
	}
	var upid string
	if err := c.Post(ctx, path.Join("/nodes", node, "lxc", strconv.Itoa(vmid), "move_volume"), url.Values{
		"volume":  {volume},
		"storage": {storage},
		"digest":  {digest},
		"delete":  {"1"},
	}, &upid); err != nil {
		return fmt.Errorf("move LXC persistent volume: %w", err)
	}
	if upid == "" {
		return errors.New("Proxmox did not return an LXC volume move task")
	}
	if err := c.WaitTask(ctx, node, upid); err != nil {
		return fmt.Errorf("wait for LXC persistent volume move: %w", err)
	}
	return nil
}

func safePersistentLXCMountpointKey(value string) bool {
	if !strings.HasPrefix(value, "mp") {
		return false
	}
	index, err := strconv.Atoi(strings.TrimPrefix(value, "mp"))
	return err == nil && index >= 0 && index <= 30 && value == "mp"+strconv.Itoa(index)
}

func (c *Client) StartVM(ctx context.Context, node string, vmid int) error {
	var upid string
	if err := c.Post(ctx, path.Join("/nodes", node, "qemu", strconv.Itoa(vmid), "status", "start"), nil, &upid); err != nil {
		return err
	}
	if upid != "" {
		return c.WaitTask(ctx, node, upid)
	}
	return nil
}

func (c *Client) EnsureVMRunning(ctx context.Context, node string, vmid int) error {
	status, err := c.QEMUStatus(ctx, node, vmid)
	if err != nil {
		return err
	}
	if status == "running" {
		return nil
	}
	return c.StartVM(ctx, node, vmid)
}

func (c *Client) StopVM(ctx context.Context, node string, vmid int) error {
	var upid string
	if err := c.Post(ctx, path.Join("/nodes", node, "qemu", strconv.Itoa(vmid), "status", "stop"), nil, &upid); err != nil {
		return err
	}
	if upid != "" {
		return c.WaitTask(ctx, node, upid)
	}
	return nil
}

func (c *Client) CreateLXC(ctx context.Context, node string, vmid int, params url.Values) error {
	if vmid <= 0 || node == "" {
		return errors.New("Proxmox node and positive VMID are required")
	}
	if params == nil {
		params = url.Values{}
	}
	params.Set("vmid", strconv.Itoa(vmid))
	var upid string
	if err := c.Post(ctx, path.Join("/nodes", node, "lxc"), params, &upid); err != nil {
		return err
	}
	if upid != "" {
		return c.WaitTask(ctx, node, upid)
	}
	return nil
}

func (c *Client) SetLXCConfig(ctx context.Context, node string, vmid int, params url.Values) error {
	if vmid <= 0 || node == "" {
		return errors.New("Proxmox node and positive VMID are required")
	}
	return c.Put(ctx, path.Join("/nodes", node, "lxc", strconv.Itoa(vmid), "config"), params, nil)
}

func (c *Client) LXCStatus(ctx context.Context, node string, vmid int) (string, error) {
	if c == nil || node == "" || vmid <= 0 {
		return "", errors.New("Proxmox client, node, and positive VMID are required")
	}
	var status struct {
		Status string `json:"status"`
	}
	if err := c.Get(ctx, path.Join("/nodes", node, "lxc", strconv.Itoa(vmid), "status", "current"), nil, &status); err != nil {
		return "", err
	}
	if status.Status == "" {
		return "", errors.New("Proxmox LXC status response did not contain a status")
	}
	return status.Status, nil
}

func (c *Client) StopLXC(ctx context.Context, node string, vmid int) error {
	if c == nil || node == "" || vmid <= 0 {
		return errors.New("Proxmox client, node, and positive VMID are required")
	}
	var upid string
	if err := c.Post(ctx, path.Join("/nodes", node, "lxc", strconv.Itoa(vmid), "status", "stop"), nil, &upid); err != nil {
		return err
	}
	if upid != "" {
		return c.WaitTask(ctx, node, upid)
	}
	return nil
}

// destroyLXCForReplacement removes only the exact owned container configuration and rootfs.
// Detached mount-point volumes remain available for the replacement create.
func (c *Client) destroyLXCForReplacement(ctx context.Context, node string, vmid int) error {
	if c == nil || node == "" || vmid <= 0 {
		return errors.New("Proxmox client, node, and positive VMID are required")
	}
	var upid string
	if err := c.request(ctx, http.MethodDelete, path.Join("/nodes", node, "lxc", strconv.Itoa(vmid)), url.Values{
		"purge":                      {"0"},
		"destroy-unreferenced-disks": {"0"},
	}, nil, &upid); err != nil {
		return err
	}
	if upid != "" {
		return c.WaitTask(ctx, node, upid)
	}
	return nil
}

func (c *Client) StartLXC(ctx context.Context, node string, vmid int) error {
	var upid string
	if err := c.Post(ctx, path.Join("/nodes", node, "lxc", strconv.Itoa(vmid), "status", "start"), nil, &upid); err != nil {
		return err
	}
	if upid != "" {
		return c.WaitTask(ctx, node, upid)
	}
	return nil
}

func (c *Client) EnsureLXCRunning(ctx context.Context, node string, vmid int) error {
	if c == nil || node == "" || vmid <= 0 {
		return errors.New("Proxmox client, node, and positive VMID are required")
	}
	status, err := c.LXCStatus(ctx, node, vmid)
	if err != nil {
		return fmt.Errorf("read LXC guest status: %w", err)
	}
	if status == "running" {
		return nil
	}
	return c.StartLXC(ctx, node, vmid)
}

func (c *Client) QEMUConfig(ctx context.Context, node string, vmid int, out any) error {
	return c.Get(ctx, path.Join("/nodes", node, "qemu", strconv.Itoa(vmid), "config"), nil, out)
}

// QEMUStatus reads the live status endpoint separately from the guest
// configuration. Proxmox does not include a reliable running/stopped state in
// every configuration response, and destructive builder cleanup must stop a
// running VM before requesting its removal.
func (c *Client) QEMUStatus(ctx context.Context, node string, vmid int) (string, error) {
	if c == nil || node == "" || vmid <= 0 {
		return "", errors.New("Proxmox client, node, and positive VMID are required")
	}
	var status struct {
		Status string `json:"status"`
	}
	if err := c.Get(ctx, path.Join("/nodes", node, "qemu", strconv.Itoa(vmid), "status", "current"), nil, &status); err != nil {
		return "", fmt.Errorf("read QEMU guest status: %w", err)
	}
	if status.Status == "" {
		return "", errors.New("Proxmox QEMU status response did not contain a status")
	}
	return status.Status, nil
}

// GuestConfig inspects both Proxmox guest kinds for a VMID. A reserved
// identity must be held when the opposite guest kind occupies it; treating a
// kind mismatch as absence would turn an ownership collision into a create
// attempt.
func (c *Client) GuestConfig(ctx context.Context, node string, vmid int) (GuestKind, map[string]any, error) {
	var qemu map[string]any
	err := c.QEMUConfig(ctx, node, vmid, &qemu)
	if err == nil {
		return KindQEMU, qemu, nil
	}
	if !IsNotFound(err) {
		return "", nil, err
	}
	var lxc map[string]any
	err = c.LXCConfig(ctx, node, vmid, &lxc)
	if err == nil {
		return KindLXC, lxc, nil
	}
	return "", nil, err
}

// QEMUAgentNetworkInterfaces reads only guest-agent network evidence. It is
// used by explicit firewall recovery checks; no operator or module identity is
// inferred from a hostname or arbitrary user address.
func (c *Client) QEMUAgentNetworkInterfaces(ctx context.Context, node string, vmid int) ([]GuestAgentInterface, error) {
	if node == "" || vmid <= 0 {
		return nil, errors.New("node and positive VMID are required")
	}
	var response struct {
		Result []GuestAgentInterface `json:"result"`
	}
	if err := c.Get(ctx, path.Join("/nodes", node, "qemu", strconv.Itoa(vmid), "agent", "network-get-interfaces"), nil, &response); err != nil {
		return nil, fmt.Errorf("read QEMU guest-agent network interfaces: %w", err)
	}
	return response.Result, nil
}

func (c *Client) LXCConfig(ctx context.Context, node string, vmid int, out any) error {
	return c.Get(ctx, path.Join("/nodes", node, "lxc", strconv.Itoa(vmid), "config"), nil, out)
}

func (c *Client) NodeNetwork(ctx context.Context, node string, out any) error {
	if interfaces, ok := out.(*[]NetworkInterface); ok {
		if err := c.Get(ctx, path.Join("/nodes", node, "network"), nil, interfaces); err != nil {
			return err
		}
		if c.snippetRunner != nil && c.snippetAddr != "" && c.snippetUser != "" {
			if err := enrichNetworkInterfaceHardware(ctx, c.snippetRunner, c.snippetAddr, c.snippetUser, *interfaces); err != nil {
				return err
			}
		}
		return nil
	}
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
func (c *Client) UploadStorageFile(ctx context.Context, node, storage, content, source, filename, checksum string) (err error) {
	if node == "" || storage == "" || content == "" || source == "" || filename == "" || checksum == "" {
		return errors.New("node, storage, content, source, filename, and checksum are required")
	}
	started := time.Now()
	status := 0
	defer func() {
		telemetry.Record(ctx, telemetry.Event{
			Category: "proxmox_api", Operation: path.Join("/nodes", node, "storage", storage, "upload"), Method: http.MethodPost,
			Status: status, Duration: time.Since(started), Success: err == nil,
		})
	}()
	if len(checksum) != sha256.Size*2 {
		return errors.New("artifact checksum must be a SHA-256 hex digest")
	}
	if _, err := hex.DecodeString(checksum); err != nil {
		return errors.New("artifact checksum must be a SHA-256 hex digest")
	}
	if strings.ContainsAny(filename, "/\\\r\n") {
		return errors.New("uploaded filename must be a plain filename")
	}
	file, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open qualified artifact %s: %w", source, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect qualified artifact %s: %w", source, err)
	}
	prefix, suffix, contentType, err := artifactMultipartParts(content, checksum, filename)
	if err != nil {
		return err
	}
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return err
	}
	base.Path = path.Join(base.Path, "/nodes", node, "storage", storage, "upload")
	pipeReader, pipeWriter := io.Pipe()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), pipeReader)
	if err != nil {
		_ = pipeReader.Close()
		return err
	}
	request.Header.Set("Content-Type", contentType)
	request.ContentLength = int64(len(prefix)) + info.Size() + int64(len(suffix))
	if c.Token != "" {
		request.Header.Set("Authorization", c.Token)
	}
	streamErr := make(chan error, 1)
	go func() {
		if _, err := pipeWriter.Write(prefix); err != nil {
			_ = pipeWriter.CloseWithError(err)
			streamErr <- err
			return
		}
		if _, err := io.Copy(pipeWriter, file); err != nil {
			_ = pipeWriter.CloseWithError(fmt.Errorf("read qualified artifact %s: %w", source, err))
			streamErr <- err
			return
		}
		if _, err := pipeWriter.Write(suffix); err != nil {
			_ = pipeWriter.CloseWithError(err)
			streamErr <- err
			return
		}
		streamErr <- pipeWriter.Close()
	}()
	response, err := c.HTTP.Do(request)
	if err != nil {
		_ = pipeReader.CloseWithError(err)
		_ = <-streamErr
		return err
	}
	status = response.StatusCode
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		_ = pipeReader.CloseWithError(err)
		_ = <-streamErr
		return err
	}
	if err := <-streamErr; err != nil {
		return fmt.Errorf("stream qualified artifact %s: %w", source, err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &APIError{StatusCode: response.StatusCode, Status: response.Status, Message: strings.TrimSpace(string(data))}
	}
	var result struct {
		UPID string `json:"data"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode Proxmox upload response: %w", err)
	}
	if result.UPID != "" {
		if err := c.WaitTask(ctx, node, result.UPID); err != nil {
			return fmt.Errorf("wait for Proxmox artifact upload: %w", err)
		}
	}
	return nil
}

// artifactMultipartParts builds the fixed multipart framing separately from
// the artifact bytes. This keeps uploads streamed while allowing the request
// to send Content-Length, which pveproxy requires for file uploads.
func artifactMultipartParts(content, checksum, filename string) ([]byte, []byte, string, error) {
	var body bytes.Buffer
	multipartWriter := multipart.NewWriter(&body)
	if err := multipartWriter.WriteField("content", content); err != nil {
		return nil, nil, "", err
	}
	if err := multipartWriter.WriteField("checksum-algorithm", "sha256"); err != nil {
		return nil, nil, "", err
	}
	if err := multipartWriter.WriteField("checksum", checksum); err != nil {
		return nil, nil, "", err
	}
	if _, err := multipartWriter.CreateFormFile("filename", filename); err != nil {
		return nil, nil, "", err
	}
	prefixLength := body.Len()
	if err := multipartWriter.Close(); err != nil {
		return nil, nil, "", err
	}
	full := body.Bytes()
	prefix := append([]byte(nil), full[:prefixLength]...)
	suffix := append([]byte(nil), full[prefixLength:]...)
	return prefix, suffix, multipartWriter.FormDataContentType(), nil
}

// UploadStorageText uploads deterministic non-secret cloud-init content to a
// snippets storage class without creating a controller-side plaintext file.
func (c *Client) UploadStorageText(ctx context.Context, node, storage, content, filename, value string) (err error) {
	if node == "" || storage == "" || content == "" || filename == "" {
		return errors.New("node, storage, content, and filename are required")
	}
	if strings.ContainsAny(filename, "/\\\r\n") {
		return errors.New("uploaded filename must be a plain filename")
	}
	if content == "snippets" && c.snippetRunner != nil {
		if storage != "local" || c.snippetAddr == "" || c.snippetUser == "" {
			return errors.New("SSH snippet upload requires the local storage and bootstrap host identity")
		}
		return uploadSnippetViaSSH(ctx, c.snippetRunner, c.snippetAddr, c.snippetUser, filename, value)
	}
	started := time.Now()
	status := 0
	defer func() {
		telemetry.Record(ctx, telemetry.Event{
			Category: "proxmox_api", Operation: path.Join("/nodes", node, "storage", storage, "upload"), Method: http.MethodPost,
			Status: status, Duration: time.Since(started), Success: err == nil,
		})
	}()
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
	status = response.StatusCode
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

func uploadSnippetViaSSH(ctx context.Context, runner StdinCommandRunner, address, user, filename, value string) error {
	if runner == nil || address == "" || user == "" || filename == "" {
		return errors.New("SSH snippet upload identity is incomplete")
	}
	command := privilegedCommand(user, "install -D -m 0644 /dev/stdin "+shellQuote("/var/lib/vz/snippets/"+filename))
	if _, err := runner.RunWithStdin(ctx, address, user, command, strings.NewReader(value)); err != nil {
		return fmt.Errorf("upload Proxmox snippet over SSH: %w", err)
	}
	return nil
}

// DeleteStorageSnippet deletes only a plain, generated snippet filename. It
// deliberately does not expose arbitrary storage-content deletion to module
// code or callers handling untrusted paths.
func (c *Client) DeleteStorageSnippet(ctx context.Context, node, storage, filename string) error {
	if node == "" || storage == "" || filename == "" || strings.ContainsAny(filename, "/\\\r\n") {
		return errors.New("node, storage, and plain snippet filename are required")
	}
	return c.Delete(ctx, path.Join("/nodes", node, "storage", storage, "content", "snippets", filename))
}

// DownloadURL asks Proxmox to download a pinned image and verify it before
// making it available in storage. The checksum is sent as an API form field,
// never placed in a shell command or a generated public artifact.
func (c *Client) DownloadURL(ctx context.Context, node, storage, filename, imageURL, checksum string) (string, error) {
	if node == "" || storage == "" || filename == "" || imageURL == "" || checksum == "" {
		return "", errors.New("node, storage, filename, image URL, and checksum are required")
	}
	parsed, err := url.Parse(imageURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", errors.New("gateway image URL must be an HTTPS URL")
	}
	if strings.ContainsAny(filename, "/\\\r\n") || len(checksum) != 128 || !isHex(checksum) {
		return "", errors.New("gateway image filename or SHA-512 checksum is invalid")
	}
	var upid string
	if err := c.Post(ctx, path.Join("/nodes", node, "storage", storage, "download-url"), url.Values{
		"content":            {"import"},
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
			if status.ExitStatus != "OK" && status.ExitStatus != "" && !strings.HasPrefix(status.ExitStatus, "WARNINGS:") {
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
	contents, err := c.StorageContent(ctx, node, storage, "import")
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
		if observed == "" {
			// PVE import listings omit checksums. Re-download the exact pinned
			// input so its task-level checksum verification establishes the
			// bytes again after a partial bootstrap attempt.
			break
		}
		if !strings.EqualFold(observed, checksum) {
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
	contents, err = c.StorageContent(ctx, node, storage, "import")
	if err != nil {
		return "", err
	}
	for _, content := range contents {
		if path.Base(content.Filename) == filename || strings.HasSuffix(content.VolID, "/"+filename) {
			observed := content.Checksum
			if observed == "" {
				observed = content.CSum
			}
			// PVE validates the requested checksum inside the completed
			// download task but does not expose it for import content in the
			// storage listing. A newly downloaded matching entry is therefore
			// qualified by the successful task; pre-existing entries still
			// require listing checksum evidence above.
			if observed == "" {
				return content.VolID, nil
			}
			if !strings.EqualFold(observed, checksum) {
				return "", fmt.Errorf("downloaded gateway image %q has no matching checksum evidence", filename)
			}
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
	_, err := c.EnsureDirectoryStorageContentWithMutation(ctx, storageID, storagePath, []string{"backup"})
	return err
}

// EnsureDirectoryStorageContent validates a named directory storage and adds
// only the requested content types. It never changes the path or adopts a
// different storage with the same name.
func (c *Client) EnsureDirectoryStorageContent(ctx context.Context, storageID, storagePath string, requiredContent []string) error {
	_, err := c.EnsureDirectoryStorageContentWithMutation(ctx, storageID, storagePath, requiredContent)
	return err
}

// EnsureDirectoryStorageContentWithMutation is the coarse mutation-aware
// form used by deployment reporting. A true result means a provider write was
// required or may have been accepted before returning an error; it is not a
// per-field audit record.
func (c *Client) EnsureDirectoryStorageContentWithMutation(ctx context.Context, storageID, storagePath string, requiredContent []string) (bool, error) {
	if c == nil {
		return false, errors.New("Proxmox client is required")
	}
	if storageID == "" || storagePath == "" || len(requiredContent) == 0 {
		return false, errors.New("storage ID and path are required")
	}
	var storages []struct {
		Storage string `json:"storage"`
		Type    string `json:"type"`
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := c.Get(ctx, "/storage", nil, &storages); err != nil {
		return false, fmt.Errorf("list Proxmox storage: %w", err)
	}
	for _, storage := range storages {
		if storage.Storage != storageID {
			continue
		}
		if storage.Type != "dir" || storage.Path != storagePath {
			return false, fmt.Errorf("Proxmox storage %q has a conflicting definition", storageID)
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
			if err := c.Put(ctx, path.Join("/storage", storageID), url.Values{"content": {strings.Join(values, ",")}}, nil); err != nil {
				return true, fmt.Errorf("extend Proxmox storage %q content: %w", storageID, err)
			}
			return true, nil
		}
		return false, nil
	}
	if err := c.Post(ctx, "/storage", url.Values{
		"storage": {storageID},
		"type":    {"dir"},
		"path":    {storagePath},
		"content": {strings.Join(requiredContent, ",")},
	}, nil); err != nil {
		return true, fmt.Errorf("create Proxmox directory storage %q: %w", storageID, err)
	}
	return true, nil
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

// EnsureLVMThinStorageWithMutation is the coarse mutation-aware form of
// EnsureLVMThinStorage. It reports only whether registration was required or
// may have been accepted before a provider error.
func (c *Client) EnsureLVMThinStorageWithMutation(ctx context.Context, storageID, volumeGroup, thinPool string) (bool, error) {
	if c == nil {
		return false, errors.New("Proxmox client is required")
	}
	if storageID == "" || volumeGroup == "" || thinPool == "" {
		return false, errors.New("storage ID, volume group, and thin pool are required")
	}
	var storages []struct {
		Storage     string `json:"storage"`
		Type        string `json:"type"`
		VolumeGroup string `json:"vgname"`
		ThinPool    string `json:"thinpool"`
		Content     string `json:"content"`
	}
	if err := c.Get(ctx, "/storage", nil, &storages); err != nil {
		return false, fmt.Errorf("list Proxmox storage: %w", err)
	}
	for _, storage := range storages {
		if storage.Storage != storageID {
			continue
		}
		if storage.Type != "lvmthin" || storage.VolumeGroup != volumeGroup || storage.ThinPool != thinPool || !strings.Contains(storage.Content, "images") || !strings.Contains(storage.Content, "rootdir") {
			return false, fmt.Errorf("Proxmox storage %q has a conflicting definition", storageID)
		}
		return false, nil
	}
	if err := c.Post(ctx, "/storage", url.Values{
		"storage": {storageID}, "type": {"lvmthin"}, "vgname": {volumeGroup}, "thinpool": {thinPool}, "content": {"images,rootdir"},
	}, nil); err != nil {
		return true, fmt.Errorf("create Proxmox guest storage %q: %w", storageID, err)
	}
	return true, nil
}

func (c *Client) CreateNodeNetwork(ctx context.Context, node string, params url.Values) error {
	return c.Post(ctx, path.Join("/nodes", node, "network"), params, nil)
}

func (c *Client) UpdateNodeNetwork(ctx context.Context, node, iface string, params url.Values) error {
	return c.Put(ctx, path.Join("/nodes", node, "network", iface), params, nil)
}

// ReloadNodeNetwork promotes and applies the pending Proxmox network
// configuration. Network create/update calls write interfaces.new on PVE 9;
// the reload endpoint is required before host-side fragments can reference a
// newly-created interface.
func (c *Client) ReloadNodeNetwork(ctx context.Context, node string) error {
	var upid string
	if err := c.Put(ctx, path.Join("/nodes", node, "network"), nil, &upid); err != nil {
		return fmt.Errorf("reload Proxmox node network: %w", err)
	}
	if upid != "" {
		if err := c.WaitTask(ctx, node, upid); err != nil {
			return fmt.Errorf("wait for Proxmox network reload: %w", err)
		}
	}
	return nil
}

func IsNotFound(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.StatusCode == http.StatusNotFound {
		return true
	}
	// Proxmox 9.2 reports an absent QEMU/LXC config as HTTP 500 rather than
	// HTTP 404. Keep this narrowly scoped to its exact guest-config message;
	// unrelated server errors must remain fatal.
	message := strings.TrimSpace(apiErr.Message)
	return apiErr.StatusCode == http.StatusInternalServerError && strings.HasPrefix(message, "Configuration file 'nodes/") &&
		(strings.Contains(message, "/qemu-server/") || strings.Contains(message, "/lxc/")) &&
		strings.HasSuffix(message, ".conf' does not exist")
}

func (c *Client) request(ctx context.Context, method, endpoint string, query url.Values, form url.Values, out any) (err error) {
	started := time.Now()
	status := 0
	defer func() {
		telemetry.Record(ctx, telemetry.Event{
			Category: "proxmox_api", Operation: endpoint, Method: method,
			Status: status, Duration: time.Since(started), Success: err == nil,
		})
	}()
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
	status = response.StatusCode
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
		if len(envelope.Errors) > 0 {
			errorsJSON, marshalErr := json.Marshal(envelope.Errors)
			if marshalErr == nil {
				if message == "" {
					message = string(errorsJSON)
				} else {
					message += ": " + string(errorsJSON)
				}
			}
		}
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
