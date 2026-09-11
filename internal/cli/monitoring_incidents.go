package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/observability"
)

func runMonitoringIncidents(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("module monitoring incidents", flag.ContinueOnError)
	fs.SetOutput(errOut)
	jsonOutput := fs.Bool("json", false, "emit the incident response as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return errors.New("usage: boetticher module monitoring incidents list|show|investigate [ID] [--json]")
	}
	action, id := fs.Arg(0), ""
	if fs.NArg() == 2 {
		id = fs.Arg(1)
	}
	if (action == "list" && id != "") || (action != "list" && id == "") || (action != "list" && action != "show" && action != "investigate") {
		return errors.New("usage: boetticher module monitoring incidents list|show|investigate [ID] [--json]")
	}
	config, err := loadLabConfig()
	if err != nil {
		return err
	}
	if !observability.Enabled(config.Modules) {
		return errors.New("observability is disabled")
	}
	transport, err := observabilityTransport(config)
	if err != nil {
		return err
	}
	binding, ok := observability.BindingFor("observability")
	if !ok {
		return errors.New("observability runtime binding is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := observability.HostClient{Transport: transport}
	var response string
	switch action {
	case "list":
		response, err = client.GrafanaIncidents(ctx, binding)
	case "show":
		response, err = client.GrafanaIncident(ctx, binding, id)
	case "investigate":
		response, err = client.GrafanaIncidentInvestigation(ctx, binding, id)
	}
	if err != nil {
		return err
	}
	if *jsonOutput {
		fmt.Fprintln(out, response)
		return nil
	}
	fmt.Fprintf(out, "Monitoring incident %s\n%s\n", action, strings.TrimSpace(response))
	return nil
}
