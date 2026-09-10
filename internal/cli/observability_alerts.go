package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofastercloud/boetticher/internal/clientservices"
	controllerhost "github.com/gofastercloud/boetticher/internal/controller/host"
	"github.com/gofastercloud/boetticher/internal/observability"
	"github.com/gofastercloud/boetticher/internal/pushover"
)

func runObservabilityAlerts(args []string, input io.Reader, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] != "pushover" {
		return errors.New("usage: boetticher module observability alerts pushover apply|status|test|remove [flags]")
	}
	if len(args) < 2 {
		return errors.New("usage: boetticher module observability alerts pushover apply|status|test|remove [flags]")
	}
	switch args[1] {
	case "apply":
		return applyPushover(args[2:], input, out, errOut)
	case "status":
		return statusPushover(out)
	case "test":
		return testPushover(args[2:], input, out, errOut)
	case "remove":
		return removePushover(args[2:], input, out, errOut)
	default:
		return fmt.Errorf("unknown Pushover operation %q", args[1])
	}
}

func applyPushover(args []string, input io.Reader, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("module observability alerts pushover apply", flag.ContinueOnError)
	fs.SetOutput(errOut)
	yes := fs.Bool("yes", false, "approve the intent change")
	enabled := fs.String("enabled", "true", "enable or disable Pushover alert delivery")
	title := fs.String("title", "Boetticher observability", "notification title")
	priority := fs.Int("priority", 0, "Pushover priority from -2 to 1 (2 is reserved)")
	credentialsFile := fs.String("credentials-file", "", "import user:API credentials into the protected store")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: boetticher module observability alerts pushover apply [--credentials-file PATH] [--enabled true|false] [--title TITLE] [--priority -2..1] [--yes]")
	}
	value, err := parseBool(*enabled)
	if err != nil {
		return errors.New("--enabled must be true or false")
	}
	if *priority == 2 || *priority < -2 || *priority > 1 || !validPushoverTitle(*title) {
		return errors.New("Pushover title or priority is invalid")
	}
	if !*yes && !affirm(input, out, "Save Pushover alert intent? [y/N] ") {
		return errors.New("Pushover apply cancelled")
	}
	lock, err := acquireObservabilityLock(controllerhost.ClientServicesLockPath)
	if err != nil {
		return err
	}
	defer lock.Release()
	config, err := loadLabConfig()
	if err != nil {
		return err
	}
	var credentials pushover.Credentials
	if *credentialsFile != "" {
		credentials, err = readPushoverCredentialsFile(*credentialsFile)
		if err != nil {
			return err
		}
	}
	if config.Modules.Observability == nil {
		config.Modules.Observability = &clientservices.ObservabilityConfig{}
	}
	config.Modules.Observability.Alerts.Pushover = &clientservices.PushoverConfig{Enabled: &value, Title: *title, Priority: *priority}
	if err := saveLabConfig(config); err != nil {
		return err
	}
	if *credentialsFile != "" {
		if err := (observability.SecretStore{}).Set(pushover.CredentialName, []byte(credentials.User+":"+credentials.Token)); err != nil {
			return err
		}
	}
	fmt.Fprintln(out, "Pushover intent: saved (activation pending module observability apply --yes)")
	return nil
}

func readPushoverCredentialsFile(path string) (pushover.Credentials, error) {
	if path == "" {
		return pushover.Credentials{}, errors.New("Pushover credentials file is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return pushover.Credentials{}, errors.New("read Pushover credentials file failed")
	}
	if !info.Mode().IsRegular() {
		return pushover.Credentials{}, errors.New("Pushover credentials file must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return pushover.Credentials{}, errors.New("read Pushover credentials file failed")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(raw) > 64*1024 {
		return pushover.Credentials{}, errors.New("Pushover credentials file exceeds its bound")
	}
	credentials, err := pushover.ParseCredentials(raw)
	if err != nil {
		return pushover.Credentials{}, err
	}
	return credentials, nil
}

func statusPushover(out io.Writer) error {
	config, err := loadLabConfig()
	if err != nil {
		return err
	}
	configured := config.Modules.Observability != nil && config.Modules.Observability.Alerts.Pushover != nil
	enabled := configured && clientservices.Enabled(config.Modules.Observability.Alerts.Pushover.Enabled)
	present := false
	values, err := (observability.SecretStore{}).Load()
	if err != nil {
		return err
	}
	if _, ok := values[pushover.CredentialName]; ok {
		present = true
	}
	fmt.Fprintf(out, "Pushover alerts\n  Desired  %s\n  Secret   %s\n  Delivery pending module observability apply --yes\n", yesNo(enabled), yesNo(present))
	return nil
}

func testPushover(args []string, input io.Reader, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("module observability alerts pushover test", flag.ContinueOnError)
	fs.SetOutput(errOut)
	credentialsFile := fs.String("credentials-file", "", "file containing user:API credentials")
	yes := fs.Bool("yes", false, "approve sending one normal-priority test")
	title := fs.String("title", "Boetticher Pushover test", "test notification title")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *credentialsFile == "" {
		return errors.New("usage: boetticher module observability alerts pushover test --credentials-file PATH [--yes]")
	}
	credentials, err := readPushoverCredentialsFile(*credentialsFile)
	if err != nil {
		return err
	}
	if !*yes && !affirm(input, out, "Send one normal-priority Pushover test notification? [y/N] ") {
		return errors.New("Pushover test cancelled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	message := "Boetticher observability test notification (normal priority)."
	if err := pushover.NewClient(nil).Validate(ctx, credentials); err != nil {
		return err
	}
	if err := pushover.NewClient(nil).Send(ctx, credentials, *title, message, 0); err != nil {
		return err
	}
	fmt.Fprintln(out, "Pushover test: SENT (normal priority)")
	return nil
}

func removePushover(args []string, input io.Reader, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("module observability alerts pushover remove", flag.ContinueOnError)
	fs.SetOutput(errOut)
	yes := fs.Bool("yes", false, "approve removal")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !*yes {
		return errors.New("Pushover removal requires --yes")
	}
	lock, err := acquireObservabilityLock(controllerhost.ClientServicesLockPath)
	if err != nil {
		return err
	}
	defer lock.Release()
	config, err := loadLabConfig()
	if err != nil {
		return err
	}
	if config.Modules.Observability != nil {
		config.Modules.Observability.Alerts.Pushover = nil
	}
	if err := saveLabConfig(config); err != nil {
		return err
	}
	if _, err := (observability.SecretStore{}).Remove(pushover.CredentialName); err != nil {
		return err
	}
	fmt.Fprintln(out, "Pushover intent: removed (activation remains unchanged until module observability apply --yes)")
	return nil
}

func parseBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, errors.New("invalid boolean")
	}
}

func validPushoverTitle(value string) bool {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 250 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == ' ' || char == '.' || char == '_' || char == '-') {
			return false
		}
	}
	return true
}
