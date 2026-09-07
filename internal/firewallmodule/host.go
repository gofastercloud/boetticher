package firewallmodule

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
)

const hostImagePath = "/var/tmp/boetticher-firewall-280.img"

// HostClient is the capability's narrow Host lifecycle adapter. The public
// operator command remains boetticher; these remote commands are its internal
// implementation path and are never exposed as operator workflow.
type HostClient struct {
	Transport controllerhost.Transport
	CopyTo    func(context.Context, string, string) error
	CopyFrom  func(context.Context, string, string) error
}

type HostProviderStatus struct {
	Kind    string
	Exists  bool
	Running bool
	Config  string
}

type HostApplyResult struct {
	Created bool
	Changed bool
	Running bool
}

// CaptureProviderTrustViaHost reads the certificate from the exact VM through
// the authenticated Host's QEMU guest agent. It is bootstrap-only; normal API
// requests use the stored certificate as verified TLS trust.
func CaptureProviderTrustViaHost(ctx context.Context, host HostClient) ([]byte, error) {
	result, err := host.Run(ctx, "set -eu; qm guest exec "+itoa(ProviderVMID)+" --synchronous 1 -- /bin/busybox base64 /etc/uhttpd.crt")
	if err != nil {
		return nil, fmt.Errorf("read provider certificate through Host guest agent: %w", err)
	}
	var output struct {
		ExitCode int    `json:"exitcode"`
		Data     string `json:"out-data"`
		Error    string `json:"err-data"`
	}
	if err := json.Unmarshal(result.Stdout, &output); err != nil {
		return nil, errors.New("provider guest agent returned malformed certificate state")
	}
	if output.ExitCode != 0 {
		if detail := strings.TrimSpace(output.Error); detail != "" {
			return nil, fmt.Errorf("provider guest agent certificate command failed (%d): %s", output.ExitCode, detail)
		}
		return nil, fmt.Errorf("provider guest agent certificate command failed (%d)", output.ExitCode)
	}
	encoded := strings.Join(strings.Fields(output.Data), "")
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("provider guest agent returned invalid encoded TLS certificate")
	}
	trust, err := normalizeProviderCertificate(data)
	if err != nil {
		return nil, err
	}
	return trust, nil
}

func normalizeProviderCertificate(data []byte) ([]byte, error) {
	if block, _ := pem.Decode(data); block != nil && block.Type == "CERTIFICATE" {
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, errors.New("provider guest agent returned an invalid PEM TLS certificate")
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}), nil
	}
	certificate, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, errors.New("provider guest agent returned no usable TLS certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), nil
}

// FirewallRuntimeActiveViaHost checks the loaded nftables table through the
// exact provider VM's guest agent. Firewall4 is a reload/apply operation, not
// a resident process, so a process-state check is not sufficient.
func FirewallRuntimeActiveViaHost(ctx context.Context, host HostClient) (bool, error) {
	result, err := host.Run(ctx, "set -eu; qm guest exec "+itoa(ProviderVMID)+" --synchronous 1 -- /usr/sbin/nft list table inet fw4")
	if err != nil {
		return false, fmt.Errorf("read provider firewall runtime through Host guest agent: %w", err)
	}
	var output struct {
		ExitCode int    `json:"exitcode"`
		Data     string `json:"out-data"`
	}
	if err := json.Unmarshal(result.Stdout, &output); err != nil {
		return false, errors.New("provider guest agent returned malformed firewall runtime state")
	}
	return output.ExitCode == 0 && strings.Contains(output.Data, "table inet fw4"), nil
}

func (h HostClient) Run(ctx context.Context, command string) (controllerhost.Result, error) {
	return h.Transport.Run(ctx, command)
}

func (h HostClient) Copy(ctx context.Context, source, destination string) error {
	if h.CopyTo != nil {
		return h.CopyTo(ctx, source, destination)
	}
	if source == "" || destination == "" {
		return errors.New("Host image source and destination are required")
	}
	args, err := h.Transport.SCPArgs(source, destination)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "/usr/bin/scp", args...)
	if err := command.Run(); err != nil {
		return fmt.Errorf("copy firewall provider image to Host: %w", err)
	}
	return nil
}

func (h HostClient) CopyFromHost(ctx context.Context, source, destination string) error {
	if h.CopyFrom != nil {
		return h.CopyFrom(ctx, source, destination)
	}
	if source == "" || destination == "" {
		return errors.New("Host image source and local destination are required")
	}
	args, err := h.Transport.SCPFromArgs(source, destination)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "/usr/bin/scp", args...)
	if err := command.Run(); err != nil {
		return fmt.Errorf("copy firewall provider image from Host: %w", err)
	}
	return nil
}

func (h HostClient) RunWithStdin(ctx context.Context, command string, stdin io.Reader) (controllerhost.Result, error) {
	return h.Transport.RunWithStdin(ctx, command, stdin)
}

func ValidateHostSubstrateViaSSH(ctx context.Context, host HostClient) error {
	result, err := host.Run(ctx, "set -eu; ip link show vmbr0 >/dev/null; ip -d link show vmbr1 | grep -Eq 'vlan_filtering (1|on)'; pvesm status --storage boetticher-data | awk 'NR > 1 && $1 == \"boetticher-data\" && $3 == \"active\" { found=1 } END { exit found ? 0 : 1 }'")
	if err != nil {
		return fmt.Errorf("required Host substrate is unavailable; run or fix host apply: %w", err)
	}
	_ = result
	return nil
}

func InspectHostProvider(ctx context.Context, host HostClient) (HostProviderStatus, error) {
	result, err := host.Run(ctx, "set -eu; if qm status "+itoa(ProviderVMID)+" >/dev/null 2>&1; then printf '%s\\n' BOETTICHER_QEMU; qm status "+itoa(ProviderVMID)+"; qm config "+itoa(ProviderVMID)+"; elif pct status "+itoa(ProviderVMID)+" >/dev/null 2>&1; then printf '%s\\n' BOETTICHER_LXC; pct status "+itoa(ProviderVMID)+"; else printf '%s\\n' BOETTICHER_ABSENT; fi")
	if err != nil {
		return HostProviderStatus{}, fmt.Errorf("inspect firewall provider on Host: %w", err)
	}
	output := string(result.Stdout)
	if strings.Contains(output, "BOETTICHER_ABSENT") {
		return HostProviderStatus{}, nil
	}
	if strings.Contains(output, "BOETTICHER_LXC") {
		return HostProviderStatus{Kind: "lxc", Exists: true, Config: output}, nil
	}
	if !strings.Contains(output, "BOETTICHER_QEMU") {
		return HostProviderStatus{}, errors.New("HOLD: Host provider inspection returned an unrecognized guest kind")
	}
	return HostProviderStatus{Kind: "qemu", Exists: true, Running: strings.Contains(output, "status: running"), Config: output}, nil
}

func EnsureHostProvider(ctx context.Context, host HostClient, storage string, image Image) (HostApplyResult, error) {
	status, err := InspectHostProvider(ctx, host)
	if err != nil {
		return HostApplyResult{}, err
	}
	if !status.Exists {
		if err := requireImage(image); err != nil {
			return HostApplyResult{}, err
		}
		if err := host.Copy(ctx, image.Path, hostImagePath); err != nil {
			return HostApplyResult{}, err
		}
		create := "set -eu; image=" + shellQuote(hostImagePath) + "; trap 'rm -f \"$image\"' EXIT HUP INT TERM; qm create " + itoa(ProviderVMID) + " --name " + shellQuote(ProviderName) + " --memory 2048 --cores 2 --ostype l26 --onboot 1 --agent 1 --scsihw virtio-scsi-single --boot " + shellQuote("order=scsi0;net0") + " --serial0 socket --tags " + shellQuote("boetticher;managed;module;"+providerOwnerTag) + " --net0 " + shellQuote(hostNIC(ProviderNIC0, "vmbr0")) + " --net1 " + shellQuote(hostNIC(ProviderNIC1, "vmbr1")) + "; import_output=$(qm importdisk " + itoa(ProviderVMID) + " \"$image\" " + shellQuote(storage) + " --format raw); disk=$(printf '%s\\n' \"$import_output\" | awk -F\"'\" '/imported disk/ { print $2; exit }'); if [ -z \"$disk\" ]; then disk=$(printf '%s\\n' \"$import_output\" | awk -F': ' '/unused0:/ { print $2; exit }'); fi; test -n \"$disk\"; case \"$disk\" in " + shellQuote(storage+":") + "*) ;; *) echo 'imported firewall disk has an unexpected storage identity' >&2; exit 1 ;; esac; qm set " + itoa(ProviderVMID) + " --scsi0 \"$disk\"; qm start " + itoa(ProviderVMID)
		if _, err := host.Run(ctx, create); err != nil {
			return HostApplyResult{}, fmt.Errorf("create firewall provider %s: %w", ProviderName, err)
		}
		post, err := InspectHostProvider(ctx, host)
		if err != nil {
			return HostApplyResult{}, err
		}
		if err := validateHostProvider(post, storage); err != nil {
			return HostApplyResult{}, err
		}
		return HostApplyResult{Created: true, Changed: true, Running: post.Running}, nil
	}
	if status.Kind != "qemu" {
		return HostApplyResult{}, fmt.Errorf("HOLD: VMID %d is occupied by an unowned %s guest", ProviderVMID, status.Kind)
	}
	if err := validateHostProvider(status, storage); err != nil {
		return HostApplyResult{}, err
	}
	changed := false
	if !strings.Contains(status.Config, "scsi0:") {
		disk := unusedDisk(status.Config, storage)
		command := ""
		if disk != "" {
			command = "qm set " + itoa(ProviderVMID) + " --scsi0 " + shellQuote(disk)
		} else {
			if err := requireImage(image); err != nil {
				return HostApplyResult{}, err
			}
			if err := host.Copy(ctx, image.Path, hostImagePath); err != nil {
				return HostApplyResult{}, err
			}
			command = "set -eu; image=" + shellQuote(hostImagePath) + "; trap 'rm -f \"$image\"' EXIT HUP INT TERM; import_output=$(qm importdisk " + itoa(ProviderVMID) + " \"$image\" " + shellQuote(storage) + " --format raw); disk=$(printf '%s\\n' \"$import_output\" | awk -F\"'\" '/imported disk/ { print $2; exit }'); if [ -z \"$disk\" ]; then disk=$(printf '%s\\n' \"$import_output\" | awk -F': ' '/unused0:/ { print $2; exit }'); fi; test -n \"$disk\"; case \"$disk\" in " + shellQuote(storage+":") + "*) ;; *) echo 'imported firewall disk has an unexpected storage identity' >&2; exit 1 ;; esac; qm set " + itoa(ProviderVMID) + " --scsi0 \"$disk\""
		}
		if _, err := host.Run(ctx, command); err != nil {
			return HostApplyResult{}, fmt.Errorf("attach firewall provider disk: %w", err)
		}
		changed = true
	}
	if !status.Running {
		if _, err := host.Run(ctx, "qm start "+itoa(ProviderVMID)); err != nil {
			return HostApplyResult{}, fmt.Errorf("start firewall provider: %w", err)
		}
		changed = true
	}
	post, err := InspectHostProvider(ctx, host)
	if err != nil {
		return HostApplyResult{}, err
	}
	if err := validateHostProvider(post, storage); err != nil {
		return HostApplyResult{}, err
	}
	return HostApplyResult{Changed: changed, Running: post.Running}, nil
}

// RebootHostProvider performs the provider lifecycle rehearsal through the
// enrolled Host. It accepts a stopped owned provider by starting it, and
// otherwise performs a shutdown/start cycle without exposing qm to operators.
func RebootHostProvider(ctx context.Context, host HostClient, storage string) error {
	status, err := InspectHostProvider(ctx, host)
	if err != nil {
		return err
	}
	if err := validateHostProvider(status, storage); err != nil {
		return err
	}
	command := "set -eu; if qm status " + itoa(ProviderVMID) + " | grep -Fqx 'status: running'; then qm shutdown " + itoa(ProviderVMID) + " --timeout 60; fi; for attempt in $(seq 1 60); do qm status " + itoa(ProviderVMID) + " | grep -Fqx 'status: stopped' && break; sleep 1; done; qm status " + itoa(ProviderVMID) + " | grep -Fqx 'status: stopped'; qm start " + itoa(ProviderVMID)
	if _, err := host.Run(ctx, command); err != nil {
		return fmt.Errorf("reboot firewall provider: %w", err)
	}
	post, err := InspectHostProvider(ctx, host)
	if err != nil {
		return err
	}
	if err := validateHostProvider(post, storage); err != nil {
		return err
	}
	if !post.Running {
		return errors.New("firewall provider did not return to running state after reboot")
	}
	return nil
}

func DestroyHostProvider(ctx context.Context, host HostClient, storage string) error {
	status, err := InspectHostProvider(ctx, host)
	if err != nil {
		return err
	}
	if !status.Exists {
		return nil
	}
	if status.Kind != "qemu" {
		return fmt.Errorf("HOLD: VMID %d is occupied by an unowned %s guest", ProviderVMID, status.Kind)
	}
	if err := validateHostProvider(status, storage); err != nil {
		return err
	}
	command := "set -eu; if qm status " + itoa(ProviderVMID) + " | grep -Fqx 'status: running'; then qm shutdown " + itoa(ProviderVMID) + " --timeout 60; fi; qm destroy " + itoa(ProviderVMID) + " --purge 1 --destroy-unreferenced-disks 1"
	if _, err := host.Run(ctx, command); err != nil {
		return fmt.Errorf("remove firewall provider: %w", err)
	}
	post, err := InspectHostProvider(ctx, host)
	if err != nil {
		return err
	}
	if post.Exists {
		return errors.New("HOLD: firewall provider still exists after teardown")
	}
	return nil
}

func validateHostProvider(status HostProviderStatus, storage string) error {
	if !status.Exists || status.Kind != "qemu" {
		return errors.New("HOLD: expected QEMU firewall provider is absent")
	}
	if !strings.Contains(status.Config, "name: "+ProviderName) {
		return fmt.Errorf("HOLD: VMID %d has the wrong provider name", ProviderVMID)
	}
	if !strings.Contains(status.Config, providerOwnerTag) || !strings.Contains(status.Config, "tags: ") {
		return errors.New("HOLD: firewall provider ownership tag is absent")
	}
	if !nicMatches(configLine(status.Config, "net0"), ProviderNIC0, "vmbr0") || !nicMatches(configLine(status.Config, "net1"), ProviderNIC1, "vmbr1") {
		return errors.New("HOLD: firewall provider NIC shape is not the expected vmbr0/vmbr1 pair")
	}
	for _, line := range strings.Split(status.Config, "\n") {
		if strings.HasPrefix(line, "net") && !strings.HasPrefix(line, "net0:") && !strings.HasPrefix(line, "net1:") {
			return fmt.Errorf("HOLD: firewall provider has undeclared network interface %s", strings.SplitN(line, ":", 2)[0])
		}
	}
	if disk := configLine(status.Config, ProviderDisk); disk != "" && !strings.HasPrefix(disk, storage+":") {
		return fmt.Errorf("HOLD: firewall provider disk is not on %s", storage)
	}
	if disk := configLine(status.Config, "unused0"); disk != "" && !strings.HasPrefix(disk, storage+":") {
		return fmt.Errorf("HOLD: firewall provider unused disk is not on %s", storage)
	}
	return nil
}

func unusedDisk(config, storage string) string {
	disk := configLine(config, "unused0")
	if strings.HasPrefix(disk, storage+":") {
		return disk
	}
	return ""
}

func requireImage(image Image) error {
	if image.Path == "" || image.Name == "" || image.SHA256 == "" {
		return errors.New("qualified provider image is required for first creation")
	}
	return nil
}

func hostNIC(apiNIC, bridge string) string {
	nic, ok := parseNIC(apiNIC)
	if !ok {
		return ""
	}
	return "virtio=" + nic.MAC + ",bridge=" + bridge + ",firewall=1"
}

type parsedNIC struct {
	Model    string
	MAC      string
	Bridge   string
	Firewall string
}

func parseNIC(value string) (parsedNIC, bool) {
	parts := strings.Split(value, ",")
	if len(parts) == 0 || parts[0] == "" {
		return parsedNIC{}, false
	}
	nic := parsedNIC{Model: parts[0]}
	if model, mac, ok := strings.Cut(parts[0], "="); ok {
		nic.Model, nic.MAC = model, mac
	}
	for _, part := range parts[1:] {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch key {
		case "macaddr":
			nic.MAC = value
		case "bridge":
			nic.Bridge = value
		case "firewall":
			nic.Firewall = value
		}
	}
	return nic, nic.Model != "" && nic.MAC != ""
}

func nicMatches(observed, expected, bridge string) bool {
	got, gotOK := parseNIC(observed)
	want, wantOK := parseNIC(expected)
	return gotOK && wantOK && got.Model == want.Model && strings.EqualFold(got.MAC, want.MAC) && got.Bridge == bridge && got.Firewall == "1"
}

func configLine(config, key string) string {
	prefix := key + ": "
	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func itoa(value int) string {
	return fmt.Sprintf("%d", value)
}
