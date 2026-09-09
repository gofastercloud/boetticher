package observability

import (
	"context"
	"errors"
	"fmt"
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

func collectionTeardownCommand(target Target) string {
	tlsDir := targetTLSDir(target)
	marker := fmt.Sprintf("/var/lib/boetticher/observability/collection/%s.managed", target.Name)
	return fmt.Sprintf("set -eu; marker=%s; if [ ! -f \"$marker\" ]; then exit 0; fi; systemctl disable --now %s systemd-journal-upload.service || true; for path in /etc/systemd/system/%s /etc/boetticher/observability/node-exporter-web.yml /etc/systemd/journal-upload.conf.d/boetticher.conf /etc/systemd/system/systemd-journal-upload.service.d/boetticher.conf; do if [ -f \"$path\" ] && grep -Fq 'Boetticher observability collection' \"$path\"; then rm -f -- \"$path\"; fi; done; rm -f -- %s/node-exporter.crt.pem %s/node-exporter.key.pem %s/node-exporter.csr.pem %s/journal-upload.crt.pem %s/journal-upload.key.pem %s/journal-upload.csr.pem \"$marker\"; systemctl daemon-reload", shellQuoteValue(marker), NodeExporterService, NodeExporterService, shellQuoteValue(tlsDir), shellQuoteValue(tlsDir), shellQuoteValue(tlsDir), shellQuoteValue(tlsDir), shellQuoteValue(tlsDir), shellQuoteValue(tlsDir))
}

var errorsCollectionDomain = fmt.Errorf("collection domain is invalid")
