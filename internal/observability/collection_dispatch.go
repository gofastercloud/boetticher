package observability

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	pathpkg "path"
	"strings"
	"syscall"
	"time"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"golang.org/x/crypto/bcrypt"
)

const (
	collectionInstallerPath = "/usr/local/libexec/boetticher-install-observability-collection"
	collectionAssetRoot     = "/var/lib/boetticher/observability/collection-assets"
	maxCollectionOutput     = 1 << 20
)

// LocalRunner is the bounded Controller-local execution boundary used for
// collection installation. Tests can inject it without running a live shell.
type LocalRunner interface {
	Runner
	RunWithStdin(context.Context, string, io.Reader) (controllerhost.Result, error)
}

// BoundedLocalRunner executes only bounded, caller-constructed helper
// commands and caps both output streams. Collection target values are checked
// before reaching this boundary and are shell-quoted by the caller.
type BoundedLocalRunner struct {
	Timeout time.Duration
	Shell   string
}

func (r BoundedLocalRunner) Run(ctx context.Context, command string) (controllerhost.Result, error) {
	return r.run(ctx, command, nil)
}

func (r BoundedLocalRunner) RunWithStdin(ctx context.Context, command string, stdin io.Reader) (controllerhost.Result, error) {
	if stdin == nil {
		return controllerhost.Result{}, errors.New("local runner stdin is required")
	}
	return r.run(ctx, command, stdin)
}

func (r BoundedLocalRunner) run(ctx context.Context, command string, stdin io.Reader) (controllerhost.Result, error) {
	if strings.TrimSpace(command) == "" {
		return controllerhost.Result{}, errors.New("local runner command is required")
	}
	if err := ctx.Err(); err != nil {
		return controllerhost.Result{}, err
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	shell := r.Shell
	if shell == "" {
		shell = "/bin/sh"
	}
	process := exec.CommandContext(commandCtx, shell, "-c", command)
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	process.Stdin = stdin
	var stdout, stderr boundedCollectionBuffer
	process.Stdout, process.Stderr = &stdout, &stderr
	err := process.Run()
	result := controllerhost.Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err == nil {
		return result, nil
	}
	result.ExitCode = 1
	if exitErr := new(exec.ExitError); errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
	}
	if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
		return result, fmt.Errorf("local collection command timed out: %w", commandCtx.Err())
	}
	detail := strings.TrimSpace(string(result.Stderr))
	if detail != "" {
		return result, fmt.Errorf("local collection command failed: %w: %s", err, detail)
	}
	return result, fmt.Errorf("local collection command failed: %w", err)
}

type boundedCollectionBuffer struct{ data []byte }

func (b *boundedCollectionBuffer) Write(data []byte) (int, error) {
	remaining := maxCollectionOutput - len(b.data)
	if remaining > 0 {
		if len(data) > remaining {
			b.data = append(b.data, data[:remaining]...)
		} else {
			b.data = append(b.data, data...)
		}
	}
	return len(data), nil
}

func (b *boundedCollectionBuffer) Bytes() []byte { return bytes.Clone(b.data) }

// ReconcileCollection installs the receiver scrape configuration and then
// dispatches the same verified collection installer to the three owned Linux
// targets. Providers and their HTTPS frontend must already be ready when this
// method is called by ReconcileGuestWithTLS.
func (c HostClient) ReconcileCollection(ctx context.Context, b Binding, payloadRoot, publicDomain string, config CollectionConfig) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("collection configuration: %w", err)
	}
	if !clientservices.ValidPublicDomain(publicDomain) {
		return errorsCollectionDomain
	}
	host, ok := c.Transport.(StdinRunner)
	if !ok {
		return errors.New("collection transport cannot stream the installed helper")
	}
	local := c.LocalRunner
	if local == nil {
		local = BoundedLocalRunner{}
	}
	if err := validateCollectionPayloadRoot(payloadRoot); err != nil {
		return err
	}
	// Read every payload before the first write. This is the collection
	// preflight boundary and prevents partial staging from a missing asset.
	helper, err := osReadFile(payloadRoot + "/controller/proxmox/libexec/boetticher-install-observability-collection")
	if err != nil {
		return fmt.Errorf("read installed collection helper: %w", err)
	}
	catalog, err := osReadFile(payloadRoot + "/controller/observability/assets/catalog.json")
	if err != nil {
		return fmt.Errorf("read collection provider catalog: %w", err)
	}
	if _, err := c.GuestConfig(ctx, b); err != nil {
		return fmt.Errorf("verify owned collection runtime before staging: %w", err)
	}
	readToken, readHash, err := collectionReadCredential()
	if err != nil {
		return err
	}
	credentialCommand := fmt.Sprintf("pct exec %d -- sh -c %s", b.VMID, shellQuoteValue("install -d -m 0700 /var/lib/boetticher/credentials; umask 077; cat > /var/lib/boetticher/credentials/node-exporter-read-token.cred; chmod 0600 /var/lib/boetticher/credentials/node-exporter-read-token.cred"))
	if _, err := host.RunWithStdin(ctx, credentialCommand, bytes.NewReader(readToken)); err != nil {
		return fmt.Errorf("install receiver-only node exporter read credential: %w", err)
	}
	configText, err := config.VictoriaMetricsScrapeConfig(publicDomain)
	if err != nil {
		return err
	}
	configCommand := fmt.Sprintf("pct exec %d -- sh -c %s", b.VMID, shellQuoteValue("set -eu; install -d -m 0755 /etc/boetticher/observability; tmp=$(mktemp /etc/boetticher/observability/.collection.XXXXXX); trap 'rm -f -- \"$tmp\"' EXIT HUP INT TERM; cat >\"$tmp\"; chmod 0640 \"$tmp\"; chown root:root \"$tmp\"; mv -f \"$tmp\" "+CollectionConfigPath))
	if _, err := host.RunWithStdin(ctx, configCommand, bytes.NewReader([]byte(configText))); err != nil {
		return fmt.Errorf("install collection scrape configuration: %w", err)
	}
	for _, target := range config.Targets {
		if err := c.runTarget(ctx, b, target, publicDomain, readHash, helper, catalog, local, host); err != nil {
			return err
		}
	}
	return nil
}

// runTarget is deliberately the only target dispatch switch. Target identity
// has already been validated by CollectionConfig and the runtime ownership
// was verified by ReconcileCollection before any writes.
func (c HostClient) runTarget(ctx context.Context, b Binding, target Target, publicDomain string, readHash string, helper, catalog []byte, local LocalRunner, host StdinRunner) error {
	if err := validateTargetForBinding(target, b); err != nil {
		return err
	}
	collectorURL := "https://ingest." + publicDomain + ":443"
	installScript := fmt.Sprintf("BOETTICHER_OBSERVABILITY_ASSETS=%s sh %s --arch %s --name %s --address %s --kind %s --collector-url %s --read-token-hash %s", shellQuoteValue(collectionAssetRoot), shellQuoteValue(collectionInstallerPath), shellQuoteValue(target.Arch), shellQuoteValue(target.Name), shellQuoteValue(target.Address), shellQuoteValue(string(target.Kind)), shellQuoteValue(collectorURL), shellQuoteValue(readHash))
	var runner LocalRunner
	prefix := ""
	switch target.Kind {
	case TargetController:
		runner = local
	case TargetHost:
		runner = host
	case TargetRuntime:
		runner = host
		prefix = fmt.Sprintf("pct exec %d -- sh -c ", b.VMID)
		installScript = prefix + shellQuoteValue(installScript)
	default:
		return fmt.Errorf("collection target %s has unknown dispatch kind", target.Name)
	}
	if err := stageTarget(ctx, runner, prefix, collectionInstallerPath, helper, 0755); err != nil {
		return fmt.Errorf("stage collection installer on %s: %w", target.Name, err)
	}
	if err := stageTarget(ctx, runner, prefix, collectionAssetRoot+"/catalog.json", catalog, 0644); err != nil {
		return fmt.Errorf("stage collection catalog on %s: %w", target.Name, err)
	}
	if _, err := runner.Run(ctx, installScript); err != nil {
		return fmt.Errorf("install collection on %s: %w", target.Name, err)
	}
	return nil
}

func collectionReadCredential() ([]byte, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("generate node exporter read credential: %w", err)
	}
	token := []byte(base64.RawURLEncoding.EncodeToString(raw) + "\n")
	for i := range raw {
		raw[i] = 0
	}
	hash, err := bcrypt.GenerateFromPassword(token[:len(token)-1], bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("hash node exporter read credential: %w", err)
	}
	return token, string(hash), nil
}

func stageTarget(ctx context.Context, runner LocalRunner, prefix, targetPath string, data []byte, mode int) error {
	tmpPath := shellQuoteValue(targetPath + ".tmp.XXXXXX")
	command := fmt.Sprintf("set -eu; install -d -m 0750 %s; tmp=$(mktemp %s); trap 'rm -f -- \"$tmp\"' EXIT HUP INT TERM; cat >\"$tmp\"; chmod %04o \"$tmp\"; mv -f \"$tmp\" %s", shellQuoteValue(pathpkg.Dir(targetPath)), tmpPath, mode, shellQuoteValue(targetPath))
	if prefix == "" {
		// The Controller may be macOS, whose BSD install has no -D flag.
		command = fmt.Sprintf("install -d -m 0750 %s; cat > %s; chmod %04o %s", shellQuoteValue(pathpkg.Dir(targetPath)), shellQuoteValue(targetPath), mode, shellQuoteValue(targetPath))
	}
	if prefix != "" {
		command = prefix + shellQuoteValue(command)
	}
	_, err := runner.RunWithStdin(ctx, command, bytes.NewReader(data))
	return err
}

func validateTargetForBinding(target Target, b Binding) error {
	if target.Kind == TargetRuntime && (target.VMID != b.VMID || target.Name != b.Hostname || target.Address != b.Address) {
		return fmt.Errorf("collection runtime target does not match the owned guest")
	}
	return nil
}

func targetTLSDir(target Target) string {
	if target.Kind == TargetRuntime {
		return "/var/lib/boetticher/tls"
	}
	return "/var/lib/boetticher/identity/logging"
}

func validateCollectionPayloadRoot(payloadRoot string) error {
	if strings.TrimSpace(payloadRoot) == "" || !strings.HasPrefix(payloadRoot, "/") || strings.ContainsAny(payloadRoot, "\r\n\x00") {
		return errors.New("installed collection payload path is invalid")
	}
	return nil
}

// Kept as a variable to make file preflight replaceable in tests without
// introducing a filesystem-backed live collection test.
var osReadFile = func(path string) ([]byte, error) { return os.ReadFile(path) }
