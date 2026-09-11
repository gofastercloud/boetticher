package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/observability"
)

const holmesAskTimeout = 5 * time.Minute

func runMonitoringAsk(args []string, input io.Reader, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("module monitoring ask", flag.ContinueOnError)
	fs.SetOutput(errOut)
	yes := fs.Bool("yes", false, "approve the paid model request")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: boetticher module monitoring ask QUESTION [--site DIR] [--yes] [--json]")
	}
	question := strings.TrimSpace(fs.Arg(0))
	if question == "" {
		return errors.New("Holmes question is empty")
	}
	if len([]byte(question)) > 32*1024 {
		return errors.New("Holmes question exceeds its bound")
	}
	config, err := loadLabConfig()
	if err != nil {
		return err
	}
	if config.Modules.Observability == nil || !enabled(config.Modules.Observability.Enabled) || config.Modules.Observability.Monitoring.Holmes == nil || !enabled(config.Modules.Observability.Monitoring.Holmes.Enabled) {
		return errors.New("monitoring Holmes is disabled")
	}
	alias := config.Modules.Observability.Monitoring.Holmes.ModelAlias
	if !*yes && !affirm(input, out, fmt.Sprintf("Ask Holmes using model alias %s? This may incur model charges. [y/N] ", alias)) {
		return errors.New("Holmes ask cancelled")
	}
	transport, err := holmesAskTransport(config)
	if err != nil {
		return err
	}
	binding, ok := observability.BindingFor("observability")
	if !ok {
		return errors.New("observability runtime binding is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), holmesAskTimeout)
	defer cancel()
	snapshotURL := ""
	if domain := config.Modules.Observability.PublicDomain; domain != "" {
		snapshotURL = "https://labviewer." + strings.TrimSuffix(strings.ToLower(domain), ".") + "/lab/snapshot.json"
	}
	answer, err := (observability.HostClient{Transport: transport, SnapshotURL: snapshotURL}).AskHolmes(ctx, binding, alias, bytes.NewReader([]byte(question)))
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(out).Encode(map[string]string{"model_alias": alias, "answer": answer})
	}
	fmt.Fprintln(out, answer)
	return nil
}

func holmesAskTransport(config controllerhost.LabConfig) (controllerhost.Transport, error) {
	runner, err := observabilityTransport(config)
	if err != nil {
		return controllerhost.Transport{}, err
	}
	transport, ok := runner.(controllerhost.Transport)
	if !ok {
		return controllerhost.Transport{}, errors.New("Holmes ask transport does not support bounded SSH timeout")
	}
	// The shared default is intentionally short for status probes. Holmes is a
	// bounded model operation, so give its SSH process the same five-minute
	// deadline as the transient systemd unit and request context.
	transport.Timeout = holmesAskTimeout
	return transport, nil
}

func enabled(value *bool) bool {
	return value != nil && *value
}
