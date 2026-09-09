package observability

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
)

// TeardownCollection removes collection material from the same three owned
// Linux targets that apply configured. It is marker-gated, retains journals
// and provider data, and never touches the receiver's frontend certificate.
func (c HostClient) TeardownCollection(ctx context.Context, b Binding) error {
	if _, err := c.GuestConfig(ctx, b); err != nil {
		return err
	}
	if c.LocalRunner == nil {
		return errors.New("collection teardown requires the Controller-local runner")
	}
	for _, target := range DefaultCollectionConfig().Targets {
		command := collectionTeardownCommand(target)
		var runner Runner = c.Transport
		if target.Kind == TargetController {
			runner = c.LocalRunner
		} else if target.Kind == TargetRuntime {
			command = fmt.Sprintf("pct exec %d -- sh -c %s", b.VMID, shellQuoteValue(command))
		}
		if _, err := runner.Run(ctx, command); err != nil {
			return fmt.Errorf("remove collection from %s: %w", target.Name, err)
		}
	}
	return nil
}

// TeardownMediaCollection removes only the collection agent material owned on
// the fixed media QEMU guest. The exact arrstack identity is rechecked before
// any QEMU guest-agent command is issued.
func (c HostClient) TeardownMediaCollection(ctx context.Context, b Binding) error {
	if _, err := c.GuestConfig(ctx, b); err != nil {
		return err
	}
	guest, err := inspectMediaGuestFacts(ctx, c.Transport)
	if err != nil {
		return err
	}
	if !guest.Exists || !guest.Running {
		return nil
	}
	if err := c.removeMediaScrapeJob(ctx, b); err != nil {
		return err
	}
	host, ok := c.Transport.(StdinRunner)
	if !ok {
		return errors.New("media collection teardown requires bounded Host stdin")
	}
	target := Target{Name: "lab-media-01", Hostname: "lab-media-01", Address: "10.10.20.230", Kind: TargetMedia, VMID: 290, Arch: "amd64", Port: NodeExporterPort}
	result, err := host.Run(ctx, qemuCollectionCommand(target.VMID, collectionTeardownCommand(target)))
	if err != nil {
		return fmt.Errorf("remove collection from %s: %w", target.Name, err)
	}
	if _, err := parseQEMUCollectionResult(result); err != nil {
		return fmt.Errorf("remove collection from %s: %w", target.Name, err)
	}
	return nil
}

func (c HostClient) removeMediaScrapeJob(ctx context.Context, b Binding) error {
	r, err := c.Transport.Run(ctx, fmt.Sprintf("pct exec %d -- cat %s", b.VMID, shellQuoteValue(CollectionConfigPath)))
	if err != nil {
		return fmt.Errorf("read collection configuration for media teardown: %w", err)
	}
	var config map[string]interface{}
	if err := yaml.Unmarshal(r.Stdout, &config); err != nil {
		return fmt.Errorf("decode collection configuration for media teardown: %w", err)
	}
	jobs, ok := config["scrape_configs"].([]interface{})
	if !ok {
		return errors.New("collection configuration has no scrape_configs list")
	}
	kept := make([]interface{}, 0, len(jobs))
	removed := false
	for _, raw := range jobs {
		job, ok := raw.(map[string]interface{})
		if !ok {
			return errors.New("collection configuration has malformed scrape job")
		}
		if jobName, _ := job["job_name"].(string); jobName == "boetticher-lab-media-01" {
			removed = true
			continue
		}
		kept = append(kept, job)
	}
	if !removed {
		return nil
	}
	config["scrape_configs"] = kept
	payload, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("encode collection configuration for media teardown: %w", err)
	}
	stager, ok := c.Transport.(StdinRunner)
	if !ok {
		return errors.New("media teardown requires bounded receiver stdin")
	}
	command := fmt.Sprintf("pct exec %d -- sh -c %s", b.VMID, shellQuoteValue("set -eu; tmp=$(mktemp /etc/boetticher/observability/.collection.teardown.XXXXXX); trap 'rm -f -- \"$tmp\"' EXIT HUP INT TERM; cat >\"$tmp\"; chmod 0640 \"$tmp\"; chown root:root \"$tmp\"; mv -f \"$tmp\" "+CollectionConfigPath))
	if _, err := stager.RunWithStdin(ctx, command, bytes.NewReader(payload)); err != nil {
		return fmt.Errorf("remove media collection scrape job: %w", err)
	}
	return nil
}

func collectionTeardownCommand(target Target) string {
	tlsDir := targetTLSDir(target)
	marker := fmt.Sprintf("/var/lib/boetticher/observability/collection/%s.managed", target.Name)
	return fmt.Sprintf("set -eu; marker=%s; if [ ! -f \"$marker\" ]; then exit 0; fi; systemctl disable --now %s systemd-journal-upload.service || true; for path in /etc/systemd/system/%s /etc/boetticher/observability/node-exporter-web.yml /etc/systemd/journal-upload.conf.d/boetticher.conf /etc/systemd/system/systemd-journal-upload.service.d/boetticher.conf; do if [ -f \"$path\" ] && grep -Fq 'Boetticher observability collection' \"$path\"; then rm -f -- \"$path\"; fi; done; rm -f -- %s/node-exporter.crt.pem %s/node-exporter.key.pem %s/node-exporter.csr.pem %s/journal-upload.crt.pem %s/journal-upload.key.pem %s/journal-upload.csr.pem \"$marker\"; systemctl daemon-reload", shellQuoteValue(marker), NodeExporterService, NodeExporterService, shellQuoteValue(tlsDir), shellQuoteValue(tlsDir), shellQuoteValue(tlsDir), shellQuoteValue(tlsDir), shellQuoteValue(tlsDir), shellQuoteValue(tlsDir))
}

var errorsCollectionDomain = fmt.Errorf("collection domain is invalid")
