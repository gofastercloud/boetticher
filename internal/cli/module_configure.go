package cli

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/modules"
	"github.com/gofastercloud/boetticher/internal/site"
)

const maxConfigureInputBytes = 64 * 1024

type configureStringList []string

func (values *configureStringList) String() string { return strings.Join(*values, ",") }

func (values *configureStringList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("configure option cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

type moduleConfigureOptions struct {
	siteDir        string
	ageIdentity    string
	dryRun         bool
	json           bool
	confirm        bool
	nonInteractive bool
	enabled        string
	sets           configureStringList
	secrets        configureStringList
	usb            configureStringList
}

type moduleConfigureChange struct {
	Kind        string `json:"kind"`
	Key         string `json:"key,omitempty"`
	Description string `json:"description"`
	From        string `json:"from,omitempty"`
	To          string `json:"to,omitempty"`
	Sensitive   bool   `json:"sensitive,omitempty"`
}

type moduleConfigureReport struct {
	Module          string                    `json:"module"`
	Status          string                    `json:"status"`
	CurrentEnabled  bool                      `json:"current_enabled"`
	CurrentState    string                    `json:"current_state"`
	CurrentReason   string                    `json:"current_reason"`
	ProposedEnabled bool                      `json:"proposed_enabled"`
	Schema          []model.ModuleConfigField `json:"schema,omitempty"`
	Dependencies    []string                  `json:"dependencies,omitempty"`
	Changes         []moduleConfigureChange   `json:"changes,omitempty"`
	MissingSecrets  []string                  `json:"missing_secrets,omitempty"`
	Error           string                    `json:"error,omitempty"`
}

func runModuleConfigure(args []string, input io.Reader, out, errOut interface{ Write([]byte) (int, error) }) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: boetticher module configure MODULE [--site DIR] [--dry-run] [--json] [--confirm]")
	}
	name := args[0]
	opts, err := parseModuleConfigureOptions(args[1:])
	if err != nil {
		return err
	}
	input = newConfigureInput(input)
	report := moduleConfigureReport{Module: name, Status: "HOLD"}
	fail := func(cause error) error {
		if opts.json {
			report.Error = cause.Error()
			_ = json.NewEncoder(out).Encode(report)
		}
		return cause
	}

	config, err := site.LoadConfig(opts.siteDir)
	if err != nil {
		return fail(err)
	}
	resolvedSite, _, err := modules.Compose(config)
	if err != nil {
		return fail(err)
	}
	registry := modules.FirstPartyRegistry()
	definition, ok := registry.Definition(name)
	if !ok {
		return fail(fmt.Errorf("unknown first-party module %q", name))
	}
	currentModule, ok := findResolvedModule(resolvedSite, name)
	if !ok {
		return fail(fmt.Errorf("module %s is not resolved", name))
	}
	report.CurrentEnabled = currentModule.Enabled
	report.CurrentState = currentModule.State
	report.CurrentReason = currentModule.Reason
	report.ProposedEnabled = currentModule.Enabled
	working := config

	if opts.enabled != "" {
		enabled, parseErr := strconv.ParseBool(opts.enabled)
		if parseErr != nil {
			return fail(errors.New("--enabled must be true or false"))
		}
		if definition.Policy == modules.Mandatory && !enabled {
			return fail(fmt.Errorf("cannot disable %s: the module is mandatory", name))
		}
		if definition.Policy != modules.Mandatory {
			if err := working.Modules.Set(name, model.ModuleConfig{Enabled: &enabled}); err != nil {
				return fail(err)
			}
		}
		report.ProposedEnabled = enabled
	} else if !opts.nonInteractive && definition.Policy != modules.Mandatory {
		enabled, promptErr := promptEnable(input, out, currentModule.Enabled)
		if promptErr != nil {
			return fail(promptErr)
		}
		if err := working.Modules.Set(name, model.ModuleConfig{Enabled: &enabled}); err != nil {
			return fail(err)
		}
		report.ProposedEnabled = enabled
	}

	fields, err := registry.ConfigurationFields(name, working)
	if err != nil {
		return fail(err)
	}
	for _, assignment := range opts.sets {
		key, value, ok := strings.Cut(assignment, "=")
		if !ok || key == "" {
			return fail(errors.New("--set requires KEY=VALUE"))
		}
		if key == "enabled" {
			return fail(errors.New("use --enabled for the module lifecycle decision"))
		}
		field, found := configurationField(fields, key)
		if !found {
			return fail(fmt.Errorf("module %s has no configurable field %q", name, key))
		}
		if err := applyConfigurationField(&working, name, field, value); err != nil {
			return fail(err)
		}
	}

	if report.ProposedEnabled && !opts.nonInteractive {
		for _, field := range fields {
			current := configurationFieldValue(working.Modules.Map()[name], field.Key)
			value, promptErr := promptConfigurationField(input, out, registry, name, field, current, working)
			if promptErr != nil {
				return fail(promptErr)
			}
			if value != "" || current != "" || field.Default != "" {
				if value == "" {
					value = current
				}
				if value == "" {
					value = field.Default
				}
				if value != "" {
					if err := applyConfigurationField(&working, name, field, value); err != nil {
						return fail(err)
					}
				}
			}
			fields, err = registry.ConfigurationFields(name, working)
			if err != nil {
				return fail(err)
			}
		}
	}

	report.Schema = fields
	if report.ProposedEnabled {
		if err := validateRequiredConfiguration(fields, working.Modules.Map()[name]); err != nil {
			return fail(err)
		}
	}
	if err := configureUSB(input, out, errOut, opts, name, definition, resolvedSite, report.ProposedEnabled, &working); err != nil {
		return fail(err)
	}
	proposedSite, _, err := modules.Compose(working)
	if err != nil {
		return fail(err)
	}

	updates, missing, err := configureSecrets(opts.siteDir, resolvedSite, proposedSite, opts.ageIdentity, input, errOut, opts.nonInteractive, opts.secrets)
	if err != nil {
		return fail(err)
	}
	report.MissingSecrets = append([]string(nil), missing...)
	if len(missing) > 0 {
		return fail(fmt.Errorf("HOLD: required operator secrets are missing: %s", strings.Join(missing, ", ")))
	}
	report.Dependencies = newlyEnabledDependencies(resolvedSite, proposedSite, name)
	report.Changes = configureChanges(name, config, working, resolvedSite, proposedSite, fields, updates)
	if len(report.Changes) == 0 {
		report.Status = "NO_CHANGES"
		return emitConfigureReport(out, opts.json, report)
	}

	if opts.json {
		if opts.dryRun || !opts.confirm {
			report.Status = map[bool]string{true: "DRY_RUN", false: "PLAN_ONLY"}[opts.dryRun]
			return emitConfigureReport(out, true, report)
		}
	} else if opts.dryRun {
		report.Status = "DRY_RUN"
		renderConfigurePlan(out, report)
		return nil
	}

	if opts.nonInteractive && !opts.confirm {
		renderConfigurePlan(out, report)
		return errors.New("module configuration requires --confirm; use --dry-run to inspect the plan")
	}
	if !opts.nonInteractive {
		renderConfigurePlan(out, report)
		apply, promptErr := promptYesNo(input, out, "Apply changes? [y/N]: ", false)
		if promptErr != nil {
			return fail(promptErr)
		}
		if !apply {
			report.Status = "REFUSED"
			fmt.Fprintln(out, "Configuration not changed.")
			return nil
		}
	}
	if err := site.ApplyConfigAndPlatformSecrets(opts.siteDir, working, resolvedSite, opts.ageIdentity, updates); err != nil {
		return fail(fmt.Errorf("apply module configuration: %w", err))
	}
	report.Status = "APPLIED"
	if opts.json {
		return emitConfigureReport(out, true, report)
	}
	fmt.Fprintln(out, "Configuration saved. Deployment remains separate: run boetticher deploy when ready.")
	return nil
}

func parseModuleConfigureOptions(args []string) (moduleConfigureOptions, error) {
	fs := flag.NewFlagSet("module configure", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	opts := moduleConfigureOptions{siteDir: ".", ageIdentity: model.DefaultAgeIdentity}
	fs.StringVar(&opts.siteDir, "site", ".", "private site repository directory")
	fs.StringVar(&opts.ageIdentity, "age-identity", model.DefaultAgeIdentity, "external Age identity path")
	fs.BoolVar(&opts.dryRun, "dry-run", false, "validate and display the plan without changing the site")
	fs.BoolVar(&opts.json, "json", false, "emit a machine-readable redacted plan")
	fs.BoolVar(&opts.confirm, "confirm", false, "confirm a desired-state mutation")
	fs.BoolVar(&opts.nonInteractive, "non-interactive", false, "do not prompt; missing required inputs are HOLD")
	fs.StringVar(&opts.enabled, "enabled", "", "set module enablement to true or false")
	fs.Var(&opts.sets, "set", "set a typed operator field as KEY=VALUE; repeatable")
	fs.Var(&opts.secrets, "secret", "read and replace an operator secret from stdin; repeatable")
	fs.Var(&opts.usb, "usb", "verify and bind a USB requirement as REQUIREMENT=PORT; repeatable")
	if err := fs.Parse(args); err != nil {
		return moduleConfigureOptions{}, err
	}
	if len(fs.Args()) != 0 {
		return moduleConfigureOptions{}, errors.New("module configure accepts one module name")
	}
	if opts.json {
		opts.nonInteractive = true
	}
	return opts, nil
}

func promptEnable(input io.Reader, out io.Writer, current bool) (bool, error) {
	defaultValue := current
	prompt := "Enable module? [N]: "
	if current {
		prompt = "Enable module? [Y/n]: "
	}
	return promptYesNo(input, out, prompt, defaultValue)
}

func promptYesNo(input io.Reader, out io.Writer, prompt string, defaultValue bool) (bool, error) {
	reader := configureReader(input)
	for attempts := 0; attempts < 3; attempts++ {
		fmt.Fprint(out, prompt)
		line, err := readConfigureLine(reader)
		if err != nil {
			return false, err
		}
		if line == "" {
			return defaultValue, nil
		}
		switch strings.ToLower(line) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(out, "Please answer y or n.")
	}
	return false, errors.New("too many invalid yes/no responses")
}

func promptConfigurationField(input io.Reader, out io.Writer, registry modules.Registry, name string, field model.ModuleConfigField, current string, config model.SiteConfig) (string, error) {
	if field.Type == model.ModuleConfigObjectList {
		return promptObjectList(input, out, registry, name, field, current, config)
	}
	if field.Type == model.ModuleConfigEnum || field.Type == model.ModuleConfigModelAlias {
		fmt.Fprintf(out, "%s", field.Prompt)
		if len(field.AllowedValues) > 0 {
			fmt.Fprintf(out, " (%s)", strings.Join(field.AllowedValues, ", "))
		}
		if current != "" && !field.Sensitive {
			fmt.Fprintf(out, " [%s]", current)
		} else if field.Default != "" {
			fmt.Fprintf(out, " [%s]", field.Default)
		}
		fmt.Fprint(out, ": ")
		return readConfigureLine(configureReader(input))
	}
	if field.Sensitive {
		fmt.Fprintf(out, "%s [hidden]: ", field.Prompt)
		return readConfigureSensitiveLine(input, out, field.Key)
	}
	if current != "" {
		fmt.Fprintf(out, "%s [%s]: ", field.Prompt, current)
	} else if field.Default != "" {
		fmt.Fprintf(out, "%s [%s]: ", field.Prompt, field.Default)
	} else {
		fmt.Fprintf(out, "%s: ", field.Prompt)
	}
	return readConfigureLine(configureReader(input))
}

func promptObjectList(input io.Reader, out io.Writer, registry modules.Registry, name string, field model.ModuleConfigField, current string, config model.SiteConfig) (string, error) {
	var existing []map[string]string
	if current != "" {
		if err := json.Unmarshal([]byte(current), &existing); err != nil {
			return "", fmt.Errorf("current %s configuration is invalid", field.Key)
		}
	}
	count := len(existing)
	if count == 0 && field.MinItems > 0 {
		count = field.MinItems
	}
	fmt.Fprintf(out, "%s", field.Prompt)
	if len(existing) > 0 {
		fmt.Fprintf(out, " [%d entries]", len(existing))
	} else {
		fmt.Fprint(out, " (number of entries)")
	}
	fmt.Fprint(out, ": ")
	line, err := readConfigureLine(configureReader(input))
	if err != nil {
		return "", err
	}
	if line != "" {
		count, err = strconv.Atoi(line)
		if err != nil || count < 0 || count > field.MaxItems {
			return "", fmt.Errorf("%s requires between %d and %d entries", field.Key, field.MinItems, field.MaxItems)
		}
	}
	if count < field.MinItems {
		return "", fmt.Errorf("%s requires at least %d entries", field.Key, field.MinItems)
	}
	items := make([]map[string]string, count)
	for index := range items {
		items[index] = make(map[string]string)
		if index < len(existing) {
			for key, value := range existing[index] {
				items[index][key] = value
			}
		}
		for _, itemField := range field.ItemFields {
			resolvedField := itemField
			if resolved, resolveErr := registry.ConfigurationFields(name, config); resolveErr == nil {
				if parent, found := configurationField(resolved, field.Key); found {
					if nested, found := configurationField(parent.ItemFields, itemField.Key); found {
						resolvedField = nested
					}
				}
			}
			currentValue := items[index][itemField.Key]
			value, promptErr := promptConfigurationField(input, out, registry, name, resolvedField, currentValue, config)
			if promptErr != nil {
				return "", promptErr
			}
			if value == "" {
				value = currentValue
			}
			if value == "" {
				value = itemField.Default
			}
			items[index][itemField.Key] = value
		}
	}
	data, err := json.Marshal(items)
	if err != nil {
		return "", errors.New("encode object-list configuration")
	}
	return string(data), nil
}

func configureReader(input io.Reader) *bufio.Reader {
	if reader, ok := input.(*configureInput); ok {
		return reader.reader
	}
	if reader, ok := input.(*bufio.Reader); ok {
		return reader
	}
	return bufio.NewReader(input)
}

type configureInput struct {
	reader   *bufio.Reader
	terminal *os.File
}

func newConfigureInput(input io.Reader) *configureInput {
	configured := &configureInput{reader: configureReader(input)}
	if file, ok := input.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		configured.terminal = file
	}
	return configured
}

func (input *configureInput) Read(value []byte) (int, error) { return input.reader.Read(value) }

func readConfigureLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if len(line) > maxConfigureInputBytes || strings.ContainsRune(line, '\x00') {
		return "", errors.New("configuration input exceeds the safe limit or contains NUL")
	}
	return strings.TrimSpace(line), nil
}

func readConfigureSensitiveLine(input io.Reader, out io.Writer, name string) (string, error) {
	if configured, ok := input.(*configureInput); ok && configured.terminal != nil {
		value, err := term.ReadPassword(int(configured.terminal.Fd()))
		fmt.Fprintln(out)
		if err != nil {
			return "", fmt.Errorf("read sensitive field %s", name)
		}
		return validateConfigureValue(string(value), name)
	}
	if file, ok := input.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		value, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(out)
		if err != nil {
			return "", fmt.Errorf("read sensitive field %s", name)
		}
		return validateConfigureValue(string(value), name)
	}
	return readConfigureLine(configureReader(input))
}

func validateConfigureValue(value, name string) (string, error) {
	if len(value) == 0 {
		return "", fmt.Errorf("%s cannot be empty", name)
	}
	if len(value) > maxConfigureInputBytes || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("%s exceeds the safe input limit", name)
	}
	return value, nil
}

func configurationField(fields []model.ModuleConfigField, key string) (model.ModuleConfigField, bool) {
	for _, field := range fields {
		if field.Key == key {
			return field, true
		}
	}
	return model.ModuleConfigField{}, false
}

func configurationFieldValue(config model.ModuleConfig, key string) string {
	switch key {
	case "provider":
		return config.Provider
	case "model_alias":
		return config.ModelAlias
	case "upstreams":
		data, _ := json.Marshal(config.Upstreams)
		return string(data)
	case "models":
		data, _ := json.Marshal(config.Models)
		return string(data)
	default:
		return ""
	}
}

func applyConfigurationField(config *model.SiteConfig, name string, field model.ModuleConfigField, value string) error {
	if field.Sensitive && value == "" {
		return fmt.Errorf("%s cannot be empty", field.Key)
	}
	if field.Type != model.ModuleConfigObjectList && field.Type != model.ModuleConfigBool {
		if _, err := validateConfigureValue(value, field.Key); err != nil {
			return err
		}
	}
	if len(field.AllowedValues) > 0 && (field.Type == model.ModuleConfigEnum || field.Type == model.ModuleConfigModelAlias) && !containsConfigureString(field.AllowedValues, value) {
		return fmt.Errorf("%s must be one of the declared allowed values", field.Key)
	}
	moduleConfig := config.Modules.Map()[name]
	switch field.Key {
	case "provider":
		moduleConfig.Provider = value
	case "model_alias":
		moduleConfig.ModelAlias = value
	case "upstreams":
		var values []model.LiteLLMUpstreamConfig
		if err := decodeObjectList(value, &values); err != nil {
			return fmt.Errorf("%s must be a valid typed list", field.Key)
		}
		moduleConfig.Upstreams = values
	case "models":
		var values []model.LiteLLMModelConfig
		if err := decodeObjectList(value, &values); err != nil {
			return fmt.Errorf("%s must be a valid typed list", field.Key)
		}
		moduleConfig.Models = values
	default:
		return fmt.Errorf("module %s field %s has no typed persistence mapping", name, field.Key)
	}
	if err := config.Modules.Set(name, moduleConfig); err != nil {
		return err
	}
	return nil
}

func containsConfigureString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func decodeObjectList(value string, target any) error {
	if len(value) > maxConfigureInputBytes {
		return errors.New("object-list input exceeds the safe limit")
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("object-list contains trailing values")
	}
	return nil
}

func validateRequiredConfiguration(fields []model.ModuleConfigField, config model.ModuleConfig) error {
	for _, field := range fields {
		value := configurationFieldValue(config, field.Key)
		if value == "" && field.Default != "" {
			value = field.Default
		}
		if !field.Required || value != "" && (field.Type != model.ModuleConfigObjectList || objectListCount(value) >= field.MinItems) {
			continue
		}
		return fmt.Errorf("HOLD: required module configuration %s is missing", field.Key)
	}
	return nil
}

func objectListCount(value string) int {
	var values []any
	if json.Unmarshal([]byte(value), &values) != nil {
		return 0
	}
	return len(values)
}

type configureUSBDevice struct {
	Port      string
	VendorID  string
	ProductID string
	Serial    string
}

func configureUSB(input io.Reader, out, errOut io.Writer, opts moduleConfigureOptions, name string, definition modules.ModuleDefinition, current model.Site, enabled bool, config *model.SiteConfig) error {
	overrides, err := parseUSBOverrides(opts.usb)
	if err != nil {
		return err
	}
	for _, requirement := range definition.USBRequirements {
		binding, found := findUSBBinding(config.USBExports, name, requirement.Name)
		if found {
			if err := validateUSBBinding(requirement, binding); err != nil {
				return err
			}
		}
		port, explicit := overrides[requirement.Name]
		if explicit {
			identity, observeErr := observeUSBPort(context.Background(), current, opts.siteDir, port)
			if observeErr != nil {
				return fmt.Errorf("HOLD: cannot verify USB selection %s: %w", requirement.Name, observeErr)
			}
			candidate := configureUSBDevice{Port: port, VendorID: identity[0], ProductID: identity[1], Serial: identity[2]}
			if err := validateUSBDevice(requirement, candidate); err != nil {
				return err
			}
			setUSBBinding(config, name, requirement.Name, candidate)
			continue
		}
		if !enabled && !requirement.Required {
			continue
		}
		if !enabled && !found {
			continue
		}
		if !enabled {
			continue
		}
		if found && opts.nonInteractive {
			continue
		}
		if opts.nonInteractive {
			return fmt.Errorf("HOLD: required USB %s/%s is not configured; provide --usb %s=PORT", name, requirement.Name, requirement.Name)
		}
		observed, observeErr := discoverConfigureUSB(current, opts.siteDir, requirement)
		if observeErr != nil {
			if found {
				fmt.Fprintf(errOut, "USB discovery unavailable; retaining configured %s/%s binding.\n", name, requirement.Name)
				continue
			}
			return fmt.Errorf("HOLD: cannot discover required USB %s/%s: %w", name, requirement.Name, observeErr)
		}
		if len(observed) == 0 {
			if found {
				fmt.Fprintf(errOut, "USB discovery found no compatible replacement; retaining configured %s/%s binding.\n", name, requirement.Name)
				continue
			}
			return fmt.Errorf("HOLD: no compatible USB device was discovered for %s/%s", name, requirement.Name)
		}
		selected, selectErr := selectConfigureUSB(input, out, requirement, observed, binding, found)
		if selectErr != nil {
			return selectErr
		}
		setUSBBinding(config, name, requirement.Name, selected)
	}
	for requirement := range overrides {
		found := false
		for _, declared := range definition.USBRequirements {
			found = found || declared.Name == requirement
		}
		if !found {
			return fmt.Errorf("--usb names undeclared requirement %q", requirement)
		}
	}
	return nil
}

func discoverConfigureUSB(s model.Site, siteDir string, requirement model.USBRequirement) ([]configureUSBDevice, error) {
	observation, err := observeUSB(context.Background(), s, siteDir)
	if err != nil {
		return nil, err
	}
	devices, err := parseConfigureUSBObservation(observation)
	if err != nil {
		return nil, err
	}
	compatible := make([]configureUSBDevice, 0, len(devices))
	for _, device := range devices {
		if validateUSBDevice(requirement, device) == nil {
			compatible = append(compatible, device)
		}
	}
	return compatible, nil
}

func parseUSBOverrides(values []string) (map[string]string, error) {
	result := make(map[string]string, len(values))
	for _, value := range values {
		requirement, port, ok := strings.Cut(value, "=")
		if !ok || requirement == "" || !usbPhysicalPort.MatchString(port) || result[requirement] != "" {
			return nil, errors.New("--usb requires a unique REQUIREMENT=physical-port value")
		}
		result[requirement] = port
	}
	return result, nil
}

func parseConfigureUSBObservation(value string) ([]configureUSBDevice, error) {
	devices := make([]configureUSBDevice, 0)
	ports := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(value), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 || len(parts) > 3 || !usbPhysicalPort.MatchString(parts[0]) {
			return nil, errors.New("HOLD: USB discovery returned an invalid physical identity")
		}
		identity := strings.Split(parts[1], ":")
		if len(identity) != 2 || !validUSBID(identity[0]) || !validUSBID(identity[1]) || ports[parts[0]] {
			return nil, errors.New("HOLD: USB discovery returned an ambiguous physical identity")
		}
		device := configureUSBDevice{Port: parts[0], VendorID: strings.ToLower(identity[0]), ProductID: strings.ToLower(identity[1])}
		if len(parts) == 3 {
			device.Serial = parts[2]
		}
		if len(device.Serial) > 256 || strings.ContainsRune(device.Serial, '\x00') {
			return nil, errors.New("HOLD: USB discovery returned an unsafe serial identity")
		}
		ports[device.Port] = true
		devices = append(devices, device)
	}
	return devices, nil
}

func validUSBID(value string) bool {
	if len(value) != 4 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validateUSBDevice(requirement model.USBRequirement, device configureUSBDevice) error {
	for _, identity := range requirement.AllowedIdentities {
		if strings.EqualFold(identity.VendorID, device.VendorID) && strings.EqualFold(identity.ProductID, device.ProductID) {
			return nil
		}
	}
	return fmt.Errorf("HOLD: USB identity %s:%s is incompatible with %s", device.VendorID, device.ProductID, requirement.Name)
}

func validateUSBBinding(requirement model.USBRequirement, binding model.USBExportBinding) error {
	if !usbPhysicalPort.MatchString(binding.Port) {
		return fmt.Errorf("HOLD: configured USB port for %s is invalid", requirement.Name)
	}
	return validateUSBDevice(requirement, configureUSBDevice{Port: binding.Port, VendorID: binding.VendorID, ProductID: binding.ProductID, Serial: binding.Serial})
}

func findUSBBinding(bindings []model.USBExportBinding, module, requirement string) (model.USBExportBinding, bool) {
	for _, binding := range bindings {
		if binding.Module == module && binding.Requirement == requirement {
			return binding, true
		}
	}
	return model.USBExportBinding{}, false
}

func setUSBBinding(config *model.SiteConfig, module, requirement string, device configureUSBDevice) {
	filtered := make([]model.USBExportBinding, 0, len(config.USBExports)+1)
	for _, binding := range config.USBExports {
		if binding.Module != module || binding.Requirement != requirement {
			filtered = append(filtered, binding)
		}
	}
	config.USBExports = append(filtered, model.USBExportBinding{Module: module, Requirement: requirement, Port: device.Port, VendorID: device.VendorID, ProductID: device.ProductID, Serial: device.Serial})
}

func selectConfigureUSB(input io.Reader, out io.Writer, requirement model.USBRequirement, devices []configureUSBDevice, current model.USBExportBinding, hasCurrent bool) (configureUSBDevice, error) {
	fmt.Fprintf(out, "USB requirement: %s (%s)\nCompatible devices:\n", requirement.Name, requirement.DeviceType)
	defaultChoice := 0
	for index, device := range devices {
		marker := ""
		if hasCurrent && current.Port == device.Port {
			marker = " [current]"
			defaultChoice = index + 1
		}
		fmt.Fprintf(out, "  %d. %s at physical port %s%s\n", index+1, device.VendorID+":"+device.ProductID, device.Port, marker)
	}
	prompt := "Select device: "
	if defaultChoice > 0 {
		prompt = fmt.Sprintf("Select device [%d]: ", defaultChoice)
	}
	fmt.Fprint(out, prompt)
	line, err := readConfigureLine(configureReader(input))
	if err != nil {
		return configureUSBDevice{}, err
	}
	if line == "" && defaultChoice > 0 {
		return devices[defaultChoice-1], nil
	}
	choice, err := strconv.Atoi(line)
	if err != nil || choice < 1 || choice > len(devices) {
		return configureUSBDevice{}, errors.New("USB selection must be one of the numbered compatible devices")
	}
	return devices[choice-1], nil
}

func newlyEnabledDependencies(current, proposed model.Site, name string) []string {
	result := make([]string, 0)
	registry := modules.FirstPartyRegistry()
	seen := map[string]bool{}
	var walk func(string)
	walk = func(moduleName string) {
		definition, ok := registry.Definition(moduleName)
		if !ok {
			return
		}
		for _, dependency := range definition.DependsOn {
			if seen[dependency] {
				continue
			}
			seen[dependency] = true
			if !modules.IsEnabled(current, dependency) && modules.IsEnabled(proposed, dependency) {
				result = append(result, dependency)
			}
			walk(dependency)
		}
	}
	walk(name)
	return result
}

func configureChanges(name string, before, after model.SiteConfig, current, proposed model.Site, fields []model.ModuleConfigField, updates map[string]string) []moduleConfigureChange {
	changes := make([]moduleConfigureChange, 0)
	beforeSite, _, _ := modules.Compose(before)
	beforeEnabled := map[string]bool{}
	for _, module := range beforeSite.Modules {
		beforeEnabled[module.Name] = module.Enabled
	}
	for _, module := range proposed.Modules {
		if beforeEnabled[module.Name] != module.Enabled {
			kind := "disable"
			if module.Enabled {
				kind = "enable"
			}
			changes = append(changes, moduleConfigureChange{Kind: "module", Key: module.Name, Description: kind + " " + module.Name})
		}
	}
	for _, key := range sortedMapKeys(updates) {
		changes = append(changes, moduleConfigureChange{Kind: "secret", Key: key, Description: "set operator secret " + key, Sensitive: true, From: "[REDACTED]", To: "[REDACTED]"})
	}
	for _, binding := range after.USBExports {
		old, found := findUSBBinding(before.USBExports, binding.Module, binding.Requirement)
		if !found || old.Port != binding.Port || old.VendorID != binding.VendorID || old.ProductID != binding.ProductID || old.Serial != binding.Serial {
			changes = append(changes, moduleConfigureChange{Kind: "usb", Key: binding.Module + "/" + binding.Requirement, Description: fmt.Sprintf("bind %s/%s -> %s (%s:%s)", binding.Module, binding.Requirement, binding.Port, binding.VendorID, binding.ProductID)})
		}
	}
	beforeConfig := before.Modules.Map()[name]
	afterConfig := after.Modules.Map()[name]
	for _, field := range fields {
		from, to := configurationFieldValue(beforeConfig, field.Key), configurationFieldValue(afterConfig, field.Key)
		if from == to || from == "" && to == field.Default {
			continue
		}
		sensitive := fieldSensitive(field)
		change := moduleConfigureChange{Kind: "field", Key: name + "." + field.Key, Description: "set " + name + "." + field.Key, From: from, To: to, Sensitive: sensitive}
		if sensitive {
			change.From, change.To = "[REDACTED]", "[REDACTED]"
		}
		changes = append(changes, change)
	}
	return changes
}

func fieldSensitive(field model.ModuleConfigField) bool {
	if field.Sensitive {
		return true
	}
	for _, nested := range field.ItemFields {
		if fieldSensitive(nested) {
			return true
		}
	}
	return false
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func emitConfigureReport(out io.Writer, jsonOutput bool, report moduleConfigureReport) error {
	if jsonOutput {
		return json.NewEncoder(out).Encode(report)
	}
	renderConfigurePlan(out, report)
	return nil
}

func renderConfigurePlan(out io.Writer, report moduleConfigureReport) {
	fmt.Fprintf(out, "Module: %s\n\nCurrent enabled: %t\nProposed enabled: %t\n", report.Module, report.CurrentEnabled, report.ProposedEnabled)
	if len(report.Dependencies) > 0 {
		fmt.Fprintln(out, "Dependencies also enabled:")
		for _, dependency := range report.Dependencies {
			fmt.Fprintf(out, "  enable %s\n", dependency)
		}
	}
	fmt.Fprintln(out, "\nPlanned changes:")
	for _, change := range report.Changes {
		fmt.Fprintf(out, "  %s", change.Description)
		if change.Sensitive {
			fmt.Fprint(out, " [redacted]")
		} else if change.From != "" || change.To != "" {
			fmt.Fprintf(out, " (%s -> %s)", change.From, change.To)
		}
		fmt.Fprintln(out)
	}
}

type configureOperatorSecret struct {
	declaration model.SecretDeclaration
	module      string
}

func configureSecrets(siteDir string, current, proposed model.Site, ageIdentity string, input io.Reader, errOut io.Writer, nonInteractive bool, supplied []string) (map[string]string, []string, error) {
	operator := make(map[string]configureOperatorSecret)
	for _, declaration := range proposed.Declarations {
		for _, secret := range declaration.Secrets {
			if secret.Generation == "operator-supplied" {
				if existing, exists := operator[secret.Name]; exists && existing.module != declaration.Module {
					return nil, nil, fmt.Errorf("HOLD: operator secret %q is declared by multiple modules", secret.Name)
				}
				operator[secret.Name] = configureOperatorSecret{declaration: secret, module: declaration.Module}
			}
		}
	}
	proposedConfig := model.ConfigFromSite(proposed)
	for key, secret := range operator {
		if err := validateModuleSecretMutation(proposedConfig, secret.module, key); err != nil {
			return nil, nil, err
		}
	}
	seenSupplied := make(map[string]bool, len(supplied))
	for _, key := range supplied {
		if seenSupplied[key] {
			return nil, nil, fmt.Errorf("secret %q was supplied more than once", key)
		}
		seenSupplied[key] = true
		if _, ok := operator[key]; !ok {
			return nil, nil, fmt.Errorf("secret %q is not an operator-supplied secret declared by the proposed module configuration", key)
		}
	}
	keys := make([]string, 0, len(operator))
	for key := range operator {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	presence := map[string]bool{}
	if len(keys) > 0 {
		var err error
		presence, err = site.PlatformSecretPresence(siteDir, current, ageIdentity, keys)
		if err != nil {
			return nil, nil, fmt.Errorf("inspect encrypted platform secrets: %w", err)
		}
	}
	updates := make(map[string]string)
	for _, key := range supplied {
		value, err := readConfigureSecret(input, errOut, key)
		if err != nil {
			return nil, nil, err
		}
		updates[key] = value
	}
	retained, err := site.LoadRetainedModules(siteDir)
	if err != nil {
		return nil, nil, fmt.Errorf("load retained module state: %w", err)
	}
	missing := make([]string, 0)
	for _, key := range keys {
		if presence[key] || updates[key] != "" {
			continue
		}
		if hasRetainedModuleState(retained, operator[key].module) && operator[key].declaration.Lifecycle == model.SecretLifecycleBootstrap {
			continue
		}
		if nonInteractive {
			missing = append(missing, key)
			continue
		}
		value, err := readConfigureSecret(input, errOut, key)
		if err != nil {
			return nil, nil, err
		}
		updates[key] = value
	}
	return updates, missing, nil
}

func readConfigureSecret(input io.Reader, errOut io.Writer, name string) (string, error) {
	if configured, ok := input.(*configureInput); ok && configured.terminal != nil {
		fmt.Fprintf(errOut, "Provide secret %s: ", name)
		value, err := term.ReadPassword(int(configured.terminal.Fd()))
		fmt.Fprintln(errOut)
		if err != nil {
			return "", fmt.Errorf("read secret %s", name)
		}
		return validateOperatorSecret(value, name)
	}
	if file, ok := input.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		fmt.Fprintf(errOut, "Provide secret %s: ", name)
		value, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(errOut)
		if err != nil {
			return "", fmt.Errorf("read secret %s", name)
		}
		return validateOperatorSecret(value, name)
	}
	return readConfigureLine(configureReader(input))
}
