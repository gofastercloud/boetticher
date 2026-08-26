package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/proxmox"
	"github.com/gofastercloud/boetticher/internal/site"
)

var safeUnit = regexp.MustCompile(`^[A-Za-z0-9_.@:%+-]+$`)

func runLogs(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	unit := fs.String("unit", "", "systemd service unit, for example blocky.service")
	since := fs.String("since", "", "bounded duration such as 1h or 30m")
	priority := fs.String("priority", "", "one of emerg, alert, crit, err, warning, notice, info, debug")
	limit := fs.Int("limit", 100, "maximum number of journal entries (1-500)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return errors.New("logs accepts at most one managed HOST")
	}
	if *limit < 1 || *limit > 500 {
		return fmt.Errorf("--limit must be between 1 and 500")
	}
	if *unit != "" {
		normalized, err := normalizeJournalUnit(*unit)
		if err != nil {
			return err
		}
		*unit = normalized
	}
	validPriorities := map[string]bool{"emerg": true, "alert": true, "crit": true, "err": true, "warning": true, "notice": true, "info": true, "debug": true}
	if *priority != "" && !validPriorities[*priority] {
		return fmt.Errorf("--priority must be one of emerg, alert, crit, err, warning, notice, info, debug")
	}
	var sinceArg string
	if *since != "" {
		duration, err := time.ParseDuration(*since)
		if err != nil || duration <= 0 || duration > 7*24*time.Hour {
			return fmt.Errorf("--since must be a positive duration no longer than 168h")
		}
		sinceArg = time.Now().UTC().Add(-duration).Format(time.RFC3339)
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	host := "lab-log-01"
	if fs.NArg() > 0 {
		host = fs.Arg(0)
	}
	component, ok := findManagedEndpoint(s, host)
	if !ok {
		return fmt.Errorf("%q is not a known boetticher-managed endpoint", host)
	}
	argsForJournal := []string{"journalctl", "--no-pager", "--output=short-iso", "--lines=" + strconv.Itoa(*limit)}
	collector, collectorOK := findManagedEndpoint(s, "lab-log-01")
	if !collectorOK {
		return fmt.Errorf("mandatory logging collector lab-log-01 is not present in the desired model")
	}
	if component.Name != collector.Name {
		argsForJournal = append(argsForJournal, "--directory=/var/log/journal/remote")
	}
	argsForJournal = append(argsForJournal, "_HOSTNAME="+component.Hostname)
	if *unit != "" {
		argsForJournal = append(argsForJournal, "_SYSTEMD_UNIT="+*unit)
	}
	if sinceArg != "" {
		argsForJournal = append(argsForJournal, "--since="+sinceArg)
	}
	if *priority != "" {
		argsForJournal = append(argsForJournal, "-p", *priority)
	}
	if component.Name == collector.Name && fs.NArg() == 0 {
		fmt.Fprintln(out, "Source: collector-local journal")
	} else {
		fmt.Fprintf(out, "Source: collected journal for %s\n", component.Hostname)
	}
	runner := proxmox.SSHRunner{ConfigFile: filepath.Join(*siteDir, "generated", "ssh", "boetticher.conf"), HostAlias: collector.Name, StrictHostKey: "ask"}
	data, err := runner.RunArgs(context.Background(), collector.Address, model.DefaultAdminSSHUser, argsForJournal)
	if err != nil {
		return fmt.Errorf("read journal for %s: %w", component.Hostname, err)
	}
	// Journal text is untrusted; avoid allowing entries to control the terminal.
	clean := strings.Map(func(r rune) rune {
		if r == '\x1b' || r == '\x7f' {
			return -1
		}
		if r < 0x20 && r != '\n' && r != '\t' {
			return ' '
		}
		return r
	}, string(data))
	fmt.Fprint(out, clean)
	return nil
}

func findManagedEndpoint(s model.Site, wanted string) (model.Component, bool) {
	for _, component := range s.PlatformComponents() {
		if component.Name == wanted || component.Hostname == wanted {
			return component, true
		}
		for _, alias := range component.DNSAliases {
			if alias == wanted {
				return component, true
			}
		}
	}
	return model.Component{}, false
}

func normalizeJournalUnit(value string) (string, error) {
	if value == "" || !safeUnit.MatchString(value) || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return "", fmt.Errorf("--unit is not a safe systemd unit")
	}
	if !strings.Contains(value, ".") {
		return value + ".service", nil
	}
	return value, nil
}
