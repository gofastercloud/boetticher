package arrstack

// This file is the Host-side lifecycle for the arrstack QEMU guest.  It is
// deliberately command based: the Controller is allowed to use the enrolled
// Host's native qm/qga tools, but it must never adopt an object whose complete
// identity and disk ownership cannot be proved.

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	"github.com/gofastercloud/boetticher/internal/firewallmodule"
)

const (
	BuilderPath          = "/opt/boetticher/current/controller/proxmox/libexec/boetticher-build-arrstack-vm"
	AdapterPath          = "/opt/boetticher/current/bin/arrstack"
	GuestAdapterPath     = "/usr/local/libexec/boetticher-arrstack"
	GuestPolicyPath      = "/usr/local/sbin/boetticher-arrstack-firewall"
	GuestPolicyReceipt   = "/run/boetticher/arrstack/policy-receipt"
	ImagePath            = "/var/lib/boetticher/arrstack-image/debian-13-arrstack-amd64.qcow2"
	GuestInstallDir      = "/opt/arrstack"
	GuestComposePath     = GuestInstallDir + "/docker-compose.yml"
	GuestMediaRoot       = "/var/lib/arrstack/media"
	GuestOwnerTag        = "boetticher-module-media"
	GuestMediaPendingTag = "boetticher-arrstack-media-pending"
	GuestVLAN            = 20
	GuestGateway         = "10.10.20.1"
	GuestPrefix          = 24
	GuestRootDisk        = "scsi0"
	GuestMediaDisk       = "scsi1"
	GuestCPU             = "x86-64-v3"
	GuestAgentTimeout    = 90 * time.Second
	GuestExecTimeout     = 30
	GuestInstallTimeout  = 20 * 60
)

type GuestFacts struct {
	Exists  bool
	Running bool
	Config  map[string]string
}

type RuntimeStatus struct {
	Exists      bool
	Running     bool
	AgentReady  bool
	DockerReady bool
	AppReady    bool
	Detail      string
}

var expectedServices = []string{
	"caddy", "qbittorrent", "prowlarr", "sonarr", "radarr", "bazarr",
	"flaresolverr", "ai-subtitle-translator", "jellyfin", "jellyseerr", "trailarr", "recyclarr",
}

//go:embed manifest.json
var manifestBytes []byte

type imageManifest struct {
	Services map[string]string `json:"services"`
	Caddy    struct {
		Base string `json:"base"`
	} `json:"caddy"`
}

var expectedServiceImages = loadExpectedServiceImages()

func loadExpectedServiceImages() map[string]string {
	var manifest imageManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		panic("invalid embedded arrstack image manifest: " + err.Error())
	}
	images := make(map[string]string, len(expectedServices))
	for _, service := range expectedServices {
		image := manifest.Services[service]
		if service == "caddy" {
			image = manifest.Caddy.Base
		}
		if !strings.Contains(image, "@sha256:") {
			panic("missing immutable arrstack image for " + service)
		}
		images[service] = image
	}
	return images
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func InspectGuest(ctx context.Context, host firewallmodule.HostClient, mediaSizes ...int) (GuestFacts, error) {
	mediaGiB := MediaDiskGiB
	if len(mediaSizes) > 0 {
		mediaGiB = mediaSizes[0]
	}
	guest, err := inspectGuestRaw(ctx, host)
	if err != nil || !guest.Exists {
		return guest, err
	}
	if err := ValidateGuestConfigForSize(guest.Config, mediaGiB); err != nil {
		return GuestFacts{}, err
	}
	return guest, nil
}

func inspectGuestRaw(ctx context.Context, host firewallmodule.HostClient) (GuestFacts, error) {
	command := "set -eu; qm=0; pct=0; qm status " + strconv.Itoa(GuestVMID) + " >/dev/null 2>&1 && qm=1 || true; pct status " + strconv.Itoa(GuestVMID) + " >/dev/null 2>&1 && pct=1 || true; if [ \"$qm\" = 1 ] && [ \"$pct\" = 1 ]; then echo 'VMID is both QEMU and LXC' >&2; exit 80; fi; if [ \"$pct\" = 1 ]; then printf '%s\\n' BOETTICHER_LXC; pct status " + strconv.Itoa(GuestVMID) + "; exit 0; fi; if [ \"$qm\" = 0 ]; then printf '%s\\n' BOETTICHER_ABSENT; exit 0; fi; printf '%s\\n' BOETTICHER_QEMU; qm status " + strconv.Itoa(GuestVMID) + "; qm config " + strconv.Itoa(GuestVMID)
	result, err := host.Run(ctx, command)
	if err != nil {
		return GuestFacts{}, fmt.Errorf("inspect arrstack VM on Host: %w", err)
	}
	output := string(result.Stdout)
	if strings.Contains(output, "BOETTICHER_ABSENT") {
		return GuestFacts{}, nil
	}
	if strings.Contains(output, "BOETTICHER_LXC") {
		return GuestFacts{}, errors.New("VMID 290 is occupied by an LXC; refusing arrstack adoption")
	}
	if !strings.Contains(output, "BOETTICHER_QEMU") {
		return GuestFacts{}, errors.New("Host returned an unrecognized arrstack guest kind")
	}
	config, running, err := parseConfig(output)
	if err != nil {
		return GuestFacts{}, err
	}
	return GuestFacts{Exists: true, Running: running, Config: config}, nil
}

func parseConfig(output string) (map[string]string, bool, error) {
	config := map[string]string{}
	running := false
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "BOETTICHER_") {
			continue
		}
		if strings.HasPrefix(line, "status:") {
			running = strings.TrimSpace(strings.TrimPrefix(line, "status:")) == "running"
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if _, exists := config[key]; exists {
			return nil, false, errors.New("arrstack VM configuration repeats a key")
		}
		config[key] = strings.TrimSpace(value)
	}
	return config, running, nil
}

func parseOptions(value string) (map[string]string, error) {
	result := map[string]string{}
	for _, item := range strings.Split(value, ",") {
		key, val, ok := strings.Cut(item, "=")
		if !ok || key == "" {
			return nil, errors.New("malformed Proxmox option")
		}
		if _, exists := result[key]; exists {
			return nil, errors.New("duplicate Proxmox option")
		}
		result[key] = val
	}
	return result, nil
}

func hasTag(value, wanted string) bool {
	for _, tag := range strings.Split(value, ";") {
		if tag == wanted {
			return true
		}
	}
	return false
}

func diskOwned(value, disk string, size int) bool {
	pattern := `^` + regexp.QuoteMeta(StorageID) + `:vm-290-` + regexp.QuoteMeta(disk) + `(?:,|$)`
	if !regexp.MustCompile(pattern).MatchString(value) {
		return false
	}
	return strings.Contains(value, ",size="+strconv.Itoa(size)+"G")
}

func ValidateGuestConfig(config map[string]string) error {
	return ValidateGuestConfigForSize(config, MediaDiskGiB)
}

func ValidateGuestConfigForSize(config map[string]string, mediaGiB int) error {
	fail := func() error { return errors.New("VMID 290 is not the exact owned arrstack QEMU VM; refusing mutation") }
	if mediaGiB < 1 {
		return fail()
	}
	for key := range config {
		switch key {
		case "agent", "boot", "cores", "cpu", "digest", "ide2", "machine", "memory", "meta", "name", "net0", "numa", "onboot", "ostype", "scsi0", "scsi1", "scsihw", "serial0", "smbios1", "tags", "ipconfig0", "nameserver", "vmgenid":
		default:
			return fail()
		}
	}
	if config["name"] != GuestName || config["cpu"] != GuestCPU || config["cores"] != strconv.Itoa(CPUs) || config["memory"] != strconv.Itoa(MemoryMiB) || config["onboot"] != "0" || config["agent"] != "1" || config["ostype"] != "l26" || config["scsihw"] != "virtio-scsi-single" || !hasTag(config["tags"], "boetticher") || !hasTag(config["tags"], "managed") || !hasTag(config["tags"], "module") || !hasTag(config["tags"], GuestOwnerTag) {
		if config["name"] == GuestName && config["cpu"] != GuestCPU {
			return errors.New("media VM CPU must be x86-64-v3; update the owned VM while stopped before retrying")
		}
		return fail()
	}
	if !strings.Contains(config["boot"], "order=scsi0") || config["ipconfig0"] != "ip="+GuestAddress+"/24,gw="+GuestGateway || config["nameserver"] != GuestGateway {
		return fail()
	}
	net, err := parseOptions(config["net0"])
	if err != nil || net["bridge"] != "vmbr1" || net["tag"] != strconv.Itoa(GuestVLAN) || net["firewall"] != "1" || !strings.EqualFold(net["virtio"], GuestMAC) {
		return fail()
	}
	for key := range net {
		if key != "virtio" && key != "bridge" && key != "tag" && key != "firewall" {
			return fail()
		}
	}
	if !diskOwned(config[GuestRootDisk], "disk-0", RootDiskGiB) || !diskOwned(config[GuestMediaDisk], "disk-1", mediaGiB) {
		return fail()
	}
	if !strings.HasPrefix(config["ide2"], StorageID+":cloudinit") && !strings.HasPrefix(config["ide2"], StorageID+":vm-290-cloudinit") {
		return fail()
	}
	if config["serial0"] != "socket" {
		return fail()
	}
	return nil
}

// ValidateRecoverableGuestConfigForSize accepts only the narrow, owned shape
// left by an interrupted qm create/import. It deliberately does not accept an
// arbitrary VM with a matching name: identity is complete before a disk can be
// imported, and an unused root reference must be a VM 290 volume on our store.
func ValidateRecoverableGuestConfigForSize(config map[string]string, mediaGiB int) error {
	fail := func() error {
		return errors.New("VMID 290 is not an owned partial arrstack QEMU VM; refusing recovery")
	}
	if mediaGiB < 1 {
		return fail()
	}
	for key := range config {
		if strings.HasPrefix(key, "unused") {
			if !regexp.MustCompile(`^unused[0-9]+$`).MatchString(key) || !regexp.MustCompile(`^`+regexp.QuoteMeta(StorageID)+`:vm-290-disk-[0-9]+(?:,|$)`).MatchString(config[key]) {
				return fail()
			}
			continue
		}
		switch key {
		case "agent", "boot", "cores", "cpu", "digest", "ide2", "machine", "memory", "meta", "name", "net0", "numa", "onboot", "ostype", "scsi0", "scsi1", "scsihw", "serial0", "smbios1", "tags", "ipconfig0", "nameserver", "vmgenid":
		default:
			return fail()
		}
	}
	if config["name"] != GuestName || config["cpu"] != GuestCPU || config["cores"] != strconv.Itoa(CPUs) || config["memory"] != strconv.Itoa(MemoryMiB) || config["onboot"] != "0" || config["agent"] != "1" || config["ostype"] != "l26" || config["scsihw"] != "virtio-scsi-single" || !hasTag(config["tags"], "boetticher") || !hasTag(config["tags"], "managed") || !hasTag(config["tags"], "module") || !hasTag(config["tags"], GuestOwnerTag) {
		if config["name"] == GuestName && config["cpu"] != GuestCPU {
			return errors.New("media VM CPU must be x86-64-v3; update the owned VM while stopped before retrying")
		}
		return fail()
	}
	if !strings.Contains(config["boot"], "order=scsi0") || config["ipconfig0"] != "ip="+GuestAddress+"/24,gw="+GuestGateway || config["nameserver"] != GuestGateway || config["serial0"] != "socket" {
		return fail()
	}
	net, err := parseOptions(config["net0"])
	if err != nil || net["bridge"] != "vmbr1" || net["tag"] != strconv.Itoa(GuestVLAN) || net["firewall"] != "1" || !strings.EqualFold(net["virtio"], GuestMAC) || len(net) != 4 {
		return fail()
	}
	if !strings.HasPrefix(config["ide2"], StorageID+":cloudinit") && !strings.HasPrefix(config["ide2"], StorageID+":vm-290-cloudinit") {
		return fail()
	}
	if root, ok := config[GuestRootDisk]; ok && !diskOwned(root, "disk-0", RootDiskGiB) {
		return fail()
	}
	if media, ok := config[GuestMediaDisk]; ok && !diskOwned(media, "disk-1", mediaGiB) {
		return fail()
	}
	unused := 0
	for key := range config {
		if strings.HasPrefix(key, "unused") {
			unused++
		}
	}
	if _, root := config[GuestRootDisk]; root && unused != 0 {
		return fail()
	}
	if _, root := config[GuestRootDisk]; !root && unused > 1 {
		return fail()
	}
	return nil
}

func EnsureGuest(ctx context.Context, host firewallmodule.HostClient) error {
	return EnsureGuestWithMedia(ctx, host, MediaDiskGiB)
}

func EnsureGuestWithMedia(ctx context.Context, host firewallmodule.HostClient, mediaGiB int) error {
	if mediaGiB < 1 {
		return errors.New("arrstack media disk size must be positive")
	}
	guest, err := inspectGuestRaw(ctx, host)
	if err != nil {
		return err
	}
	if guest.Exists {
		if err := ValidateGuestConfigForSize(guest.Config, mediaGiB); err == nil {
			return nil
		}
		if err := ValidateRecoverableGuestConfigForSize(guest.Config, mediaGiB); err != nil {
			return err
		}
		return recoverGuestWithMedia(ctx, host, guest.Config, mediaGiB)
	}
	if err := requireGuestCPUFeatures(ctx, host); err != nil {
		return err
	}
	remoteImage, cleanup, err := copyAssetToHost(ctx, host, BuilderPath, "arrstack-builder")
	if err != nil {
		return err
	}
	defer cleanup()
	if _, err := host.Run(ctx, "sh "+shellQuote(remoteImage)+" "+shellQuote(ImagePath)); err != nil {
		return fmt.Errorf("build pinned arrstack VM image: %w", err)
	}
	command := "set -eu; test -r " + shellQuote(ImagePath) + "; image=" + shellQuote(ImagePath) + "; qm create " + strconv.Itoa(GuestVMID) + " --name " + shellQuote(GuestName) + " --cpu " + shellQuote(GuestCPU) + " --memory " + strconv.Itoa(MemoryMiB) + " --cores " + strconv.Itoa(CPUs) + " --ostype l26 --onboot 0 --agent 1 --scsihw virtio-scsi-single --boot " + shellQuote("order=scsi0") + " --serial0 socket --tags " + shellQuote("boetticher;managed;module;"+GuestOwnerTag+";"+GuestMediaPendingTag) + " --net0 " + shellQuote("virtio="+GuestMAC+",bridge=vmbr1,tag="+strconv.Itoa(GuestVLAN)+",firewall=1") + " --ipconfig0 " + shellQuote("ip="+GuestAddress+"/24,gw="+GuestGateway) + " --nameserver " + shellQuote(GuestGateway) + " --ide2 " + shellQuote(StorageID+":cloudinit") + "; qm importdisk " + strconv.Itoa(GuestVMID) + " \"$image\" " + shellQuote(StorageID) + " --format raw >/dev/null; disk=$(qm config " + strconv.Itoa(GuestVMID) + " | awk -F': ' '/^unused[0-9]+:/ {print $2; exit}'); test -n \"$disk\"; case \"$disk\" in " + shellQuote(StorageID+":vm-290-disk-") + "*) ;; *) echo 'unexpected arrstack root disk identity' >&2; exit 1 ;; esac; qm set " + strconv.Itoa(GuestVMID) + " --" + GuestRootDisk + " \"$disk,ssd=1\"; qm resize " + strconv.Itoa(GuestVMID) + " " + GuestRootDisk + " " + strconv.Itoa(RootDiskGiB) + "G; qm set " + strconv.Itoa(GuestVMID) + " --" + GuestMediaDisk + " " + shellQuote(StorageID+":"+strconv.Itoa(mediaGiB)+",format=raw,ssd=1") + ""
	if _, err := host.Run(ctx, command); err != nil {
		return fmt.Errorf("create arrstack VM: %w", err)
	}
	created, err := InspectGuest(ctx, host, mediaGiB)
	if err != nil {
		return err
	}
	if !created.Exists {
		return errors.New("arrstack VM was not present after creation")
	}
	return nil
}

func requireGuestCPUFeatures(ctx context.Context, host firewallmodule.HostClient) error {
	result, err := host.Run(ctx, "awk '/^flags[[:space:]]*:/ {print; exit}' /proc/cpuinfo")
	if err != nil || !hasGuestCPUFeatures(string(result.Stdout)) {
		return errors.New("Host CPU lacks the x86-64-v3 features required by the media Bun runtime")
	}
	return nil
}

func hasGuestCPUFeatures(flags string) bool {
	available := map[string]bool{}
	for _, flag := range strings.Fields(flags) {
		available[flag] = true
	}
	for _, flag := range []string{"avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "movbe", "popcnt", "sse4_1", "sse4_2", "xsave"} {
		if !available[flag] {
			return false
		}
	}
	return available["lzcnt"] || available["abm"]
}

func recoverGuestWithMedia(ctx context.Context, host firewallmodule.HostClient, config map[string]string, mediaGiB int) error {
	command := recoveryCommand(config, mediaGiB)
	if _, err := host.Run(ctx, command); err != nil {
		return fmt.Errorf("recover owned partial arrstack VM: %w", err)
	}
	guest, err := InspectGuest(ctx, host, mediaGiB)
	if err != nil {
		return err
	}
	if !guest.Exists {
		return errors.New("arrstack VM was not present after owned recovery")
	}
	return nil
}

func recoveryCommand(config map[string]string, mediaGiB int) string {
	root, hasRoot := config[GuestRootDisk]
	_, hasMedia := config[GuestMediaDisk]
	hasUnusedRoot := false
	for key := range config {
		if strings.HasPrefix(key, "unused") {
			hasUnusedRoot = true
		}
	}
	command := "set -eu; "
	if !hasRoot {
		if !hasUnusedRoot {
			command += "test -r " + shellQuote(ImagePath) + "; qm importdisk " + strconv.Itoa(GuestVMID) + " " + shellQuote(ImagePath) + " " + shellQuote(StorageID) + " --format raw >/dev/null; "
		}
		command += "disk=$(qm config " + strconv.Itoa(GuestVMID) + " | awk -F': ' '/^unused[0-9]+:/ {print $2; exit}'); test -n \"$disk\"; case \"$disk\" in " + shellQuote(StorageID+":vm-290-disk-") + "*) ;; *) echo 'unexpected arrstack root disk identity' >&2; exit 1 ;; esac; qm set " + strconv.Itoa(GuestVMID) + " --" + GuestRootDisk + " \"$disk,ssd=1\"; "
	} else {
		_ = root
	}
	command += "qm resize " + strconv.Itoa(GuestVMID) + " " + GuestRootDisk + " " + strconv.Itoa(RootDiskGiB) + "G; "
	if !hasMedia {
		command += "tags=$(qm config " + strconv.Itoa(GuestVMID) + " | awk -F': ' '$1 == \"tags\" {print $2}'); case \";$tags;\" in *\";" + GuestMediaPendingTag + ";\"*) ;; *) echo 'arrstack media allocation is not marked pending' >&2; exit 1 ;; esac; qm set " + strconv.Itoa(GuestVMID) + " --" + GuestMediaDisk + " " + shellQuote(StorageID+":"+strconv.Itoa(mediaGiB)+",format=raw,ssd=1") + "; "
	}
	return command
}

func guestExec(command string) string {
	return guestExecWithTimeout(command, GuestExecTimeout)
}

func guestExecWithTimeout(command string, timeoutSeconds int) string {
	return "qm guest exec " + strconv.Itoa(GuestVMID) + " --synchronous 1 --timeout " + strconv.Itoa(timeoutSeconds) + " -- /bin/sh -c " + shellQuote("set -eu; "+command)
}

func guestExecJSON(ctx context.Context, host firewallmodule.HostClient, command string) error {
	_, err := guestExecOutput(ctx, host, command)
	return err
}

func guestExecWithStdinJSON(ctx context.Context, host firewallmodule.HostClient, command string, input io.Reader) (string, error) {
	return guestExecWithStdinTimeoutJSON(ctx, host, command, input, GuestExecTimeout)
}

func guestExecWithStdinTimeoutJSON(ctx context.Context, host firewallmodule.HostClient, command string, input io.Reader, timeoutSeconds int) (string, error) {
	result, err := host.RunWithStdin(ctx, "qm guest exec "+strconv.Itoa(GuestVMID)+" --synchronous 1 --timeout "+strconv.Itoa(timeoutSeconds)+" --pass-stdin -- /bin/sh -c "+shellQuote("set -eu; "+command), input)
	if err != nil {
		return "", err
	}
	return parseGuestResponse(result.Stdout)
}

func guestExecLongJSON(ctx context.Context, host firewallmodule.HostClient, command string, timeoutSeconds int) error {
	_, err := guestExecLongOutput(ctx, host, command, timeoutSeconds)
	return err
}

func guestExecLongOutput(ctx context.Context, host firewallmodule.HostClient, command string, timeoutSeconds int) (string, error) {
	result, err := host.Run(ctx, guestExecWithTimeout(command, timeoutSeconds))
	if err != nil {
		return "", err
	}
	return parseGuestResponse(result.Stdout)
}

func guestExecOutput(ctx context.Context, host firewallmodule.HostClient, command string) (string, error) {
	result, err := host.Run(ctx, guestExec(command))
	if err != nil {
		return "", err
	}
	return parseGuestResponse(result.Stdout)
}

func parseGuestResponse(data []byte) (string, error) {
	var response struct {
		ExitCode *int   `json:"exitcode"`
		Data     string `json:"out-data"`
	}
	if err := json.Unmarshal(data, &response); err != nil || response.ExitCode == nil {
		return "", errors.New("arrstack guest agent returned malformed response")
	}
	if *response.ExitCode != 0 {
		return "", fmt.Errorf("arrstack guest command failed (%d); inspect the private guest installer log", *response.ExitCode)
	}
	return response.Data, nil
}

func copyAssetToHost(ctx context.Context, host firewallmodule.HostClient, source, label string) (string, func(), error) {
	if source == "" || label == "" || strings.ContainsAny(source+label, "\r\n\x00") {
		return "", func() {}, errors.New("arrstack Host asset path is invalid")
	}
	result, err := host.Run(ctx, "set -eu; p=$(mktemp /var/tmp/boetticher-"+label+".XXXXXX); case \"$p\" in /var/tmp/boetticher-"+label+".*) ;; *) exit 1;; esac; printf '%s\\n' \"$p\"")
	if err != nil {
		return "", func() {}, fmt.Errorf("prepare Host asset path: %w", err)
	}
	remote := strings.TrimSpace(string(result.Stdout))
	prefix := "/var/tmp/boetticher-" + label + "."
	if remote == "" || strings.ContainsAny(remote, "\r\n\x00") || !strings.HasPrefix(remote, prefix) {
		return "", func() {}, errors.New("Host returned an unsafe arrstack asset path")
	}
	cleanup := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = host.Run(cleanupCtx, "case "+shellQuote(remote)+" in "+prefix+"*) rm -f -- "+shellQuote(remote)+";; *) exit 1;; esac")
	}
	if err := host.Copy(ctx, source, remote); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("copy arrstack asset to Host: %w", err)
	}
	return remote, cleanup, nil
}

func InstallRuntime(ctx context.Context, host firewallmodule.HostClient, peerPort int, cloudflareToken []byte, mediaSizes ...int) error {
	return installRuntime(ctx, host, peerPort, cloudflareToken, clientservices.MediaConfig{ApplicationDomain: clientservices.DefaultMediaReference.ApplicationDomain, Aliases: clientservices.DefaultMediaReference.Aliases}, false, mediaSizes...)
}

func InstallRuntimeWithConfig(ctx context.Context, host firewallmodule.HostClient, peerPort int, cloudflareToken []byte, config clientservices.MediaConfig, mediaSizes ...int) error {
	return installRuntime(ctx, host, peerPort, cloudflareToken, config, false, mediaSizes...)
}

func InstallRuntimeWithConfigAndMonitoring(ctx context.Context, host firewallmodule.HostClient, peerPort int, cloudflareToken []byte, config clientservices.MediaConfig, monitoring bool, mediaSizes ...int) error {
	return installRuntime(ctx, host, peerPort, cloudflareToken, config, monitoring, mediaSizes...)
}

func installRuntime(ctx context.Context, host firewallmodule.HostClient, peerPort int, cloudflareToken []byte, config clientservices.MediaConfig, monitoring bool, mediaSizes ...int) error {
	if peerPort < 1 || peerPort > 65535 {
		return errors.New("arrstack peer port must be 1..65535")
	}
	mediaGiB := MediaDiskGiB
	if len(mediaSizes) > 0 {
		mediaGiB = mediaSizes[0]
	}
	guest, err := InspectGuest(ctx, host, mediaGiB)
	if err != nil {
		return err
	}
	if !guest.Exists || !guest.Running {
		return errors.New("arrstack VM must be running before runtime installation")
	}
	mediaPending := hasTag(guest.Config["tags"], GuestMediaPendingTag)
	// The VM-owned marker, rather than caller history, authorizes first-use formatting.
	if err := guestExecJSON(ctx, host, "command -v qemu-ga >/dev/null; "+mediaMountScript(mediaPending)); err != nil {
		return fmt.Errorf("prepare arrstack media disk: %w", err)
	}
	if mediaPending {
		if _, err := host.Run(ctx, clearMediaPendingTagCommand()); err != nil {
			return fmt.Errorf("clear arrstack media pending marker: %w", err)
		}
	}
	policy, err := GuestPolicyScript(peerPort, monitoring)
	if err != nil {
		return err
	}
	policyUnit := "[Unit]\nDescription=Boetticher arrstack fail-closed firewall\nBefore=docker.service\nAfter=network-online.target nftables.service\nWants=network-online.target\n\n[Service]\nType=oneshot\nExecStart=" + GuestPolicyPath + "\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n"
	policyInstall := "command -v docker >/dev/null; docker compose version >/dev/null; install -d -m 0755 /usr/local/sbin /etc/systemd/system; cat > " + GuestPolicyPath + " <<'ARRSTACK_POLICY'\n" + policyHeredoc(policy) + "cat > /etc/systemd/system/boetticher-arrstack-firewall.service <<'ARRSTACK_UNIT'\n" + policyUnit + "ARRSTACK_UNIT\nchmod 0755 " + GuestPolicyPath + "; systemctl daemon-reload; systemctl enable boetticher-arrstack-firewall.service; systemctl restart boetticher-arrstack-firewall.service; systemctl start docker; systemctl is-active --quiet docker; install -d -m 0755 " + shellQuote(GuestInstallDir) + " " + shellQuote(GuestMediaRoot)
	dockerDropinInstall := "install -d -m 0755 /etc/systemd/system/docker.service.d; cat > /etc/systemd/system/docker.service.d/boetticher-arrstack-firewall.conf <<'DOCKER_DROPIN'\n[Unit]\nRequires=boetticher-arrstack-firewall.service\nAfter=boetticher-arrstack-firewall.service\nDOCKER_DROPIN\n"
	policyInstall = dockerDropinInstall + strings.Replace(policyInstall, "systemctl start docker;", "systemctl enable docker.service; systemctl start docker;", 1)
	if err := guestExecJSON(ctx, host, policyInstall); err != nil {
		return fmt.Errorf("arrstack guest prerequisites are not ready: %w", err)
	}
	if err := streamAdapterToGuest(ctx, host); err != nil {
		return err
	}
	installTimeout, err := installerTimeoutSeconds(ctx)
	if err != nil {
		return err
	}
	pullTimeout := installTimeout - int((5*time.Minute)/time.Second)
	if pullTimeout < 1 {
		return errors.New("insufficient Controller deadline remains for the headless media image pull")
	}
	command := "ARRSTACK_MEDIA_MONITORING=" + strconv.FormatBool(monitoring) + " ARRSTACK_HEADLESS_PULL_TIMEOUT_MS=" + strconv.Itoa(pullTimeout*1000) + " ARRSTACK_PEER_PORT=" + strconv.Itoa(peerPort) + " ARRSTACK_APPLICATION_DOMAIN=" + shellQuote(config.ApplicationDomain) + " ARRSTACK_ALIAS_RADARR=" + shellQuote(config.Aliases.Radarr) + " ARRSTACK_ALIAS_SONARR=" + shellQuote(config.Aliases.Sonarr) + " ARRSTACK_ALIAS_BAZARR=" + shellQuote(config.Aliases.Bazarr) + " ARRSTACK_ALIAS_PROWLARR=" + shellQuote(config.Aliases.Prowlarr) + " ARRSTACK_ALIAS_TRAILARR=" + shellQuote(config.Aliases.Trailarr) + " ARRSTACK_STORAGE_ROOT=" + shellQuote(GuestMediaRoot) + " " + shellQuote(GuestAdapterPath) + " install --non-interactive --install-dir " + shellQuote(GuestInstallDir)
	if len(cloudflareToken) > 0 {
		if len(cloudflareToken) > 16<<10 {
			return errors.New("Cloudflare token exceeds the bounded credential size")
		}
		command = "tmp=$(mktemp /run/boetticher-cloudflare-token.XXXXXX); trap 'rm -f \"$tmp\"' EXIT HUP INT TERM; chmod 0600 \"$tmp\"; cat >\"$tmp\"; CF_API_TOKEN=\"$(cat \"$tmp\")\" " + command
		if _, err := guestExecWithStdinTimeoutJSON(ctx, host, installerGuardCommand(command, installTimeout), bytes.NewReader(cloudflareToken), installTimeout+35); err != nil {
			return fmt.Errorf("run headless arrstack installer with Cloudflare token: %w", err)
		}
	} else if err := guestExecLongJSON(ctx, host, installerGuardCommand(command, installTimeout), installTimeout+35); err != nil {
		return fmt.Errorf("run headless arrstack installer: %w", err)
	}
	if err := guestExecJSON(ctx, host, policyReceiptCaptureCommand()); err != nil {
		return fmt.Errorf("capture applied arrstack firewall receipt: %w", err)
	}
	return nil
}

func policyHeredoc(policy string) string { return policy + "ARRSTACK_POLICY\n" }

func installerGuardCommand(command string, timeoutSeconds int) string {
	return "flock -n /run/boetticher/arrstack-install.lock timeout --signal TERM --kill-after 30s " + strconv.Itoa(timeoutSeconds) + "s sh -c " + shellQuote(command)
}

func installerTimeoutSeconds(ctx context.Context) (int, error) {
	const cleanupMargin = 65 * time.Second
	deadline, ok := ctx.Deadline()
	if !ok {
		return GuestInstallTimeout, nil
	}
	remaining := time.Until(deadline) - cleanupMargin
	seconds := int(remaining / time.Second)
	if seconds < 1 {
		return 0, errors.New("insufficient Controller deadline remains for the media installer")
	}
	if seconds > GuestInstallTimeout {
		return GuestInstallTimeout, nil
	}
	return seconds, nil
}

func policyReceiptCaptureCommand() string {
	return "set -eu; install -d -m 0700 /run/boetticher/arrstack; receipt=" + shellQuote(GuestPolicyReceipt) + "; tmp=$(mktemp /run/boetticher/arrstack/policy.XXXXXX); rules=$(mktemp /run/boetticher/arrstack/rules.XXXXXX); trap 'rm -f \"$tmp\" \"$rules\"' EXIT HUP INT TERM; script_sha=$(sha256sum " + shellQuote(GuestPolicyPath) + " | awk '{print $1}'); nft --stateless list table inet boetticher_arrstack >\"$rules\"; iptables -S DOCKER-USER >>\"$rules\"; iptables -S FORWARD >>\"$rules\"; grep -Fx -- '-A FORWARD -j DOCKER-USER' \"$rules\" >/dev/null; rules_sha=$(sha256sum \"$rules\" | awk '{print $1}'); printf 'script_sha256=%s\\nrules_sha256=%s\\n' \"$script_sha\" \"$rules_sha\" >\"$tmp\"; chmod 0600 \"$tmp\"; mv -f \"$tmp\" \"$receipt\""
}

func policyAgreementCommand(peerPort int) string {
	policy, err := GuestPolicyScript(peerPort)
	if err != nil {
		panic(err)
	}
	expected := fmt.Sprintf("%x", sha256.Sum256([]byte(policy)))
	return "set -eu; receipt=" + shellQuote(GuestPolicyReceipt) + "; test -f \"$receipt\"; test ! -L \"$receipt\"; test \"$(stat -c %a \"$receipt\")\" = 600; actual_script=$(sha256sum " + shellQuote(GuestPolicyPath) + " | awk '{print $1}'); test \"$actual_script\" = " + shellQuote(expected) + "; recorded_script=$(awk -F= '$1 == \"script_sha256\" { print $2 }' \"$receipt\"); test \"$recorded_script\" = \"$actual_script\"; rules=$(mktemp /run/boetticher/arrstack/status-rules.XXXXXX); trap 'rm -f \"$rules\"' EXIT HUP INT TERM; nft --stateless list table inet boetticher_arrstack >\"$rules\"; iptables -S DOCKER-USER >>\"$rules\"; iptables -S FORWARD >>\"$rules\"; grep -Fx -- '-A FORWARD -j DOCKER-USER' \"$rules\" >/dev/null; actual_rules=$(sha256sum \"$rules\" | awk '{print $1}'); recorded_rules=$(awk -F= '$1 == \"rules_sha256\" { print $2 }' \"$receipt\"); test -n \"$recorded_rules\"; test \"$recorded_rules\" = \"$actual_rules\""
}

func streamAdapterToGuest(ctx context.Context, host firewallmodule.HostClient) (err error) {
	info, err := os.Lstat(AdapterPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return errors.New("arrstack adapter is not a private regular file")
	}
	if info.Size() <= 0 || info.Size() > 256<<20 {
		return errors.New("arrstack adapter size is outside the bounded transfer limit")
	}
	file, err := os.Open(AdapterPath)
	if err != nil {
		return fmt.Errorf("open arrstack adapter: %w", err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return fmt.Errorf("hash arrstack adapter: %w", err)
	}
	want := hex.EncodeToString(digest.Sum(nil))
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind arrstack adapter: %w", err)
	}
	const transferDir = "/run/boetticher/arrstack-transfer"
	const transferPath = transferDir + "/adapter"
	prepareTransfer := "set -eu; test -d /run; test ! -L /run; if test -e /run/boetticher; then test -d /run/boetticher; test ! -L /run/boetticher; else install -d -m 0700 /run/boetticher; fi; if test -e " + transferDir + "; then test -d " + transferDir + "; test ! -L " + transferDir + "; fi; install -d -m 0700 " + transferDir + "; rm -f " + transferPath
	if err := guestExecJSON(ctx, host, prepareTransfer); err != nil {
		return fmt.Errorf("prepare guest adapter transfer: %w", err)
	}
	defer func() {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancelCleanup()
		cleanupErr := guestExecJSON(cleanupCtx, host, "if test -e "+transferDir+"; then test ! -L "+transferDir+"; test -d "+transferDir+"; rm -f "+transferPath+"; rmdir "+transferDir+"; fi")
		if cleanupErr != nil {
			if err == nil {
				err = fmt.Errorf("cleanup guest adapter transfer: %w", cleanupErr)
			} else {
				err = fmt.Errorf("%w; cleanup guest adapter transfer: %v", err, cleanupErr)
			}
		}
	}()
	installed, err := guestExecOutput(ctx, host, "if test -f "+shellQuote(GuestAdapterPath)+" && test ! -L "+shellQuote(GuestAdapterPath)+" && test \"$(stat -c '%u %a' "+shellQuote(GuestAdapterPath)+")\" = '0 755'; then sha256sum "+shellQuote(GuestAdapterPath)+"; else printf '%s\\n' MISSING; fi")
	if err == nil && strings.HasPrefix(installed, want+" ") {
		return nil
	}
	const chunkSize = 512 << 10
	remaining := info.Size()
	for remaining > 0 {
		n := int64(chunkSize)
		if remaining < n {
			n = remaining
		}
		chunk := make([]byte, n)
		if _, err := io.ReadFull(file, chunk); err != nil {
			return fmt.Errorf("read arrstack adapter chunk: %w", err)
		}
		if _, err := guestExecWithStdinJSON(ctx, host, "cat >> "+transferPath, bytes.NewReader(chunk)); err != nil {
			return fmt.Errorf("stream arrstack adapter through guest agent: %w", err)
		}
		remaining -= n
	}
	result, err := guestExecOutput(ctx, host, "sha256sum "+transferPath)
	if err != nil {
		return fmt.Errorf("verify guest adapter transfer: %w", err)
	}
	got := strings.Fields(result)
	if len(got) == 0 || got[0] != want {
		return errors.New("arrstack adapter checksum changed during guest transfer")
	}
	if err := guestExecJSON(ctx, host, "install -m 0755 "+transferPath+" "+shellQuote(GuestAdapterPath)); err != nil {
		return fmt.Errorf("install arrstack adapter in guest: %w", err)
	}
	return nil
}

func mediaMountScript(allowFormat bool) string {
	format := "test -b \"$device\"; blkid \"$device\" >/dev/null 2>&1"
	if allowFormat {
		format = "test -b \"$device\"; " + mediaFormatCommand("\"$device\"")
	}
	return "set -eu; device=/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi1; " + format + "; test \"$(blkid -o value -s TYPE \"$device\")\" = ext4; uuid=$(blkid -s UUID -o value \"$device\"); test -n \"$uuid\"; install -d -m 0755 /var/lib/arrstack/media; entry=\"UUID=$uuid /var/lib/arrstack/media ext4 noatime,nofail,x-systemd.before=docker.service 0 2\"; existing=$(awk '$2 == \"/var/lib/arrstack/media\" {print}' /etc/fstab 2>/dev/null || true); test -z \"$existing\" || test \"$existing\" = \"$entry\"; if ! findmnt -rn --mountpoint /var/lib/arrstack/media >/dev/null 2>&1; then test -n \"$existing\" || printf '%s\\n' \"$entry\" >> /etc/fstab; mount /var/lib/arrstack/media; fi; " + mediaMountUUIDCheckCommand("$uuid")
}

func mediaBlankCheckCommand(device string) string {
	return "signatures=$(wipefs -n " + device + " 2>/dev/null); test -z \"$signatures\"; cmp -n 1048576 " + device + " /dev/zero >/dev/null"
}

func mediaFormatCommand(device string) string {
	return "if ! blkid " + device + " >/dev/null 2>&1; then " + mediaBlankCheckCommand(device) + "; mkfs.ext4 -F " + device + "; fi"
}

func mediaMountUUIDCheckCommand(uuid string) string {
	return "test \"$(findmnt -rn -o UUID --mountpoint /var/lib/arrstack/media)\" = \"" + uuid + "\""
}

func clearMediaPendingTagCommand() string {
	return "set -eu; tags=$(qm config " + strconv.Itoa(GuestVMID) + " | awk -F': ' '$1 == \"tags\" {print $2}'); kept=$(printf '%s\\n' \"$tags\" | tr ';' '\\n' | awk '$0 != \"" + GuestMediaPendingTag + "\" && $0 != \"\"' | paste -sd';' -); if [ -n \"$kept\" ]; then qm set " + strconv.Itoa(GuestVMID) + " --tags \"$kept\"; else qm set " + strconv.Itoa(GuestVMID) + " --delete tags; fi"
}

func Start(ctx context.Context, host firewallmodule.HostClient, mediaSizes ...int) error {
	guest, err := InspectGuest(ctx, host, mediaSizes...)
	if err != nil {
		return err
	}
	if !guest.Exists {
		return errors.New("arrstack VM is absent")
	}
	if !guest.Running {
		if _, err := host.Run(ctx, "qm start "+strconv.Itoa(GuestVMID)); err != nil {
			return fmt.Errorf("start arrstack VM: %w", err)
		}
	}
	return waitGuestAgent(ctx, host)
}

func waitGuestAgent(ctx context.Context, host firewallmodule.HostClient) error {
	deadline := time.Now().Add(GuestAgentTimeout)
	for time.Now().Before(deadline) {
		if _, err := host.Run(ctx, "qm guest cmd "+strconv.Itoa(GuestVMID)+" ping"); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return errors.New("arrstack QEMU guest agent did not become ready")
}

func ReadStatus(ctx context.Context, host firewallmodule.HostClient, mediaSizes ...int) (RuntimeStatus, error) {
	return ReadStatusWithPeerPort(ctx, host, QBitTorrentPort, mediaSizes...)
}

// ReadStatusWithPeerPort verifies the runtime against the currently intended
// peer port. A different applied firewall port is drift, even when containers
// happen to be running.
func ReadStatusWithPeerPort(ctx context.Context, host firewallmodule.HostClient, peerPort int, mediaSizes ...int) (RuntimeStatus, error) {
	return readStatusWithConfig(ctx, host, peerPort, clientservices.MediaConfig{ApplicationDomain: "media.example.com", Aliases: clientservices.MediaAliases{Radarr: "radarr"}}, mediaSizes...)
}

func ReadStatusWithConfig(ctx context.Context, host firewallmodule.HostClient, peerPort int, config clientservices.MediaConfig, mediaSizes ...int) (RuntimeStatus, error) {
	return readStatusWithConfig(ctx, host, peerPort, config, mediaSizes...)
}

// AdapterBytesAgree checks the installed adapter only at apply time.  Status
// probes deliberately avoid hashing the large adapter on every invocation.
func AdapterBytesAgree(ctx context.Context, host firewallmodule.HostClient) (bool, error) {
	info, err := os.Lstat(AdapterPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() <= 0 || info.Size() > 256<<20 {
		return false, errors.New("arrstack adapter is not a private regular file")
	}
	file, err := os.Open(AdapterPath)
	if err != nil {
		return false, fmt.Errorf("open arrstack adapter: %w", err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return false, fmt.Errorf("hash arrstack adapter: %w", err)
	}
	want := hex.EncodeToString(digest.Sum(nil))
	installed, err := guestExecOutput(ctx, host, "if test -f "+shellQuote(GuestAdapterPath)+" && test ! -L "+shellQuote(GuestAdapterPath)+" && test \"$(stat -c '%u %a' "+shellQuote(GuestAdapterPath)+")\" = '0 755'; then sha256sum "+shellQuote(GuestAdapterPath)+"; else printf '%s\\n' MISSING; fi")
	if err != nil {
		return false, fmt.Errorf("inspect installed arrstack adapter: %w", err)
	}
	return strings.HasPrefix(installed, want+" "), nil
}

func readStatusWithConfig(ctx context.Context, host firewallmodule.HostClient, peerPort int, config clientservices.MediaConfig, mediaSizes ...int) (RuntimeStatus, error) {
	if peerPort < 1 || peerPort > 65535 {
		return RuntimeStatus{}, errors.New("arrstack peer port must be 1..65535")
	}
	guest, err := InspectGuest(ctx, host, mediaSizes...)
	if err != nil {
		return RuntimeStatus{}, err
	}
	status := RuntimeStatus{Exists: guest.Exists, Running: guest.Running}
	if !guest.Exists {
		status.Detail = "guest is absent"
		return status, nil
	}
	if !guest.Running {
		status.Detail = "guest is stopped"
		return status, nil
	}
	result, err := host.Run(ctx, guestExec(runtimeProbeCommandWithConfig(peerPort, config)))
	if err != nil {
		status.Detail = "guest runtime is not ready"
		return status, nil
	}
	var response struct {
		ExitCode *int   `json:"exitcode"`
		Data     string `json:"out-data"`
	}
	if err := json.Unmarshal(result.Stdout, &response); err != nil || response.ExitCode == nil {
		return RuntimeStatus{}, errors.New("arrstack guest agent returned malformed status")
	}
	if *response.ExitCode != 0 {
		status.Detail = "guest runtime probe failed"
		return status, nil
	}
	status.AgentReady = true
	status.DockerReady, status.AppReady = parseRuntimeProbe(response.Data)
	if status.AppReady {
		status.Detail = "guest runtime ready"
	} else {
		status.Detail = "guest runtime is not ready"
	}
	return status, nil
}

func parseRuntimeProbe(data string) (dockerReady, appReady bool) {
	dockerReady = strings.Contains(data, "DOCKER_READY")
	appReady = dockerReady && strings.Contains(data, "APP_READY") && strings.Contains(data, "POLICY_READY") && strings.Contains(data, "CADDY_TLS_READY")
	return dockerReady, appReady
}

func runtimeProbeCommand(peerPort int) string {
	return runtimeProbeCommandWithConfig(peerPort, clientservices.MediaConfig{ApplicationDomain: "media.example.com", Aliases: clientservices.MediaAliases{Radarr: "radarr"}})
}

func runtimeProbeCommandWithConfig(peerPort int, config clientservices.MediaConfig) string {
	serviceImages := make([]string, 0, len(expectedServices))
	for _, service := range expectedServices {
		serviceImages = append(serviceImages, service+"="+expectedServiceImages[service])
	}
	services := strings.Join(serviceImages, " ")
	compose := shellQuote(GuestComposePath)
	qbit := qbitReadinessCommand(peerPort, compose)
	probeHost := config.Aliases.Radarr + "." + config.ApplicationDomain
	return "systemctl is-active --quiet qemu-guest-agent; systemctl is-active --quiet docker && printf '%s\\n' DOCKER_READY || true; test -x " + shellQuote(GuestAdapterPath) + " && test -s " + shellQuote(GuestInstallDir+"/state.json") + " && test -s " + compose + " && printf '%s\\n' APP_STATE_READY || true; if sh -ec " + shellQuote(policyAgreementCommand(peerPort)) + "; then printf '%s\\n' POLICY_READY; fi; if test -s " + shellQuote(GuestInstallDir+"/state.json") + " && test -s " + compose + "; then for expectation in " + services + "; do service=${expectation%%=*}; expected=${expectation#*=}; cid=$(docker compose -f " + compose + " ps -q \"$service\"); test -n \"$cid\"; state=$(docker inspect -f '{{.State.Status}}' \"$cid\"); test \"$state\" = running || test \"$service\" = recyclarr; health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \"$cid\"); test \"$health\" = healthy || test \"$health\" = none || test \"$service\" = recyclarr; image=$(docker inspect -f '{{.Config.Image}}' \"$cid\"); test \"$image\" = \"$expected\"; done; " + qbit + "; printf '%s\\n' APP_READY; fi; if ss -lnt | grep -F -- '10.10.20.230:443' >/dev/null && docker compose -f " + compose + " exec -T caddy caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 && curl --fail --silent --show-error --connect-timeout 3 --resolve " + shellQuote(probeHost) + ":443:10.10.20.230 https://" + shellQuote(probeHost) + "/ -o /dev/null; then printf '%s\\n' CADDY_TLS_READY; fi"
}

func qbitReadinessCommand(peerPort int, compose string) string {
	port := strconv.Itoa(peerPort)
	config := shellQuote("/config/qBittorrent/qBittorrent.conf")
	prefs := "grep -Fx " + shellQuote("Connection\\PortRangeMin="+port) + " " + config + " && grep -Fx " + shellQuote("Connection\\PortRangeMax="+port) + " " + config
	sockets := qbitSocketReadinessCommand(peerPort)
	return "qbit=$(docker compose -f " + compose + " ps -q qbittorrent); test -n \"$qbit\"; test \"$(docker port \"$qbit\" " + shellQuote(port+"/tcp") + ")\" = \"10.10.20.230:" + port + "\"; test \"$(docker port \"$qbit\" " + shellQuote(port+"/udp") + ")\" = \"10.10.20.230:" + port + "\"; docker compose -f " + compose + " exec -T qbittorrent sh -c " + shellQuote("set -eu; "+sockets+"; "+prefs)
}

func qbitSocketReadinessCommand(peerPort int) string {
	return qbitSocketReadinessCommandForPaths(peerPort, "/proc/net/tcp", "/proc/net/udp")
}

func qbitSocketReadinessCommandForPaths(peerPort int, tcpPath, udpPath string) string {
	hexPort := fmt.Sprintf("%04X", peerPort)
	return "hex=" + shellQuote(hexPort) + "; awk -v suffix=\":$hex\" '$2 ~ suffix\"$\" && $4 == \"0A\" {found=1} END {exit !found}' " + shellQuote(tcpPath) + "; awk -v suffix=\":$hex\" '$2 ~ suffix\"$\" && $4 == \"07\" {found=1} END {exit !found}' " + shellQuote(udpPath)
}

// HasRetainedCaddyCredential checks only presence and private permissions; it
// never reads or returns the token.
func HasRetainedCaddyCredential(ctx context.Context, host firewallmodule.HostClient) (bool, error) {
	output, err := guestExecOutput(ctx, host, retainedCredentialProbeCommand())
	if err != nil {
		return false, errors.New("inspect retained private Caddy credential: guest agent unavailable")
	}
	return parseRetainedCredentialProbe(output), nil
}

func retainedCredentialProbeCommand() string {
	path := shellQuote(GuestInstallDir + "/caddy/caddy.env")
	return "if test -f " + path + " && test -s " + path + " && test \"$(stat -c %a " + path + ")\" = 600 && grep -q '^CF_API_TOKEN=.' " + path + "; then printf present; else printf missing; fi"
}

func parseRetainedCredentialProbe(output string) bool {
	return strings.TrimSpace(output) == "present"
}

func Teardown(ctx context.Context, host firewallmodule.HostClient, mediaSizes ...int) error {
	guest, err := InspectGuest(ctx, host, mediaSizes...)
	if err != nil {
		return err
	}
	if !guest.Exists || !guest.Running {
		return nil
	}
	if _, err := host.Run(ctx, "qm shutdown "+strconv.Itoa(GuestVMID)+" --timeout 90"); err != nil {
		return fmt.Errorf("stop arrstack VM: %w", err)
	}
	if _, err := host.Run(ctx, "for i in $(seq 1 90); do qm status "+strconv.Itoa(GuestVMID)+" | grep -Fqx 'status: stopped' && exit 0; sleep 1; done; exit 1"); err != nil {
		return errors.New("arrstack VM did not stop within the bounded timeout")
	}
	final, err := InspectGuest(ctx, host, mediaSizes...)
	if err != nil {
		return err
	}
	if final.Running {
		return errors.New("arrstack VM remains running after teardown")
	}
	return nil
}
