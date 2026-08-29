package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/site"
)

func runDNS(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: boetticher dns record add|list|remove")
	}
	if args[0] != "record" {
		return fmt.Errorf("unknown dns command %q", args[0])
	}
	if len(args) < 2 {
		return errors.New("usage: boetticher dns record add|list|remove")
	}
	action := args[1]
	fs := flag.NewFlagSet("dns record "+action, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	name := fs.String("name", "", "record name inside the private lab namespace")
	recordType := fs.String("type", "", "record type: A or CNAME")
	value := fs.String("value", "", "IPv4 address for A or private FQDN for CNAME")
	jsonOutput := fs.Bool("json", false, "write JSON output")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("dns record does not accept positional arguments")
	}
	config, resolved, err := loadComposedConfig(*siteDir)
	if err != nil {
		return err
	}
	switch action {
	case "list":
		records := append([]model.UserDNSRecord(nil), config.DNSRecords...)
		sort.Slice(records, func(i, j int) bool {
			if records[i].Name != records[j].Name {
				return records[i].Name < records[j].Name
			}
			return records[i].Type < records[j].Type
		})
		if *jsonOutput {
			return writeCLIJSON(out, records)
		}
		for _, record := range records {
			fmt.Fprintf(out, "%s %s %s\n", record.Name, record.Type, record.Value)
		}
		return nil
	case "add":
		return addDNSRecord(*siteDir, config, resolved, *name, *recordType, *value, *jsonOutput, out)
	case "remove":
		return removeDNSRecord(*siteDir, config, resolved, *name, *recordType, *jsonOutput, out)
	default:
		return fmt.Errorf("unknown dns record command %q", action)
	}
}

func addDNSRecord(siteDir string, config model.SiteConfig, resolved model.Site, name, recordType, value string, jsonOutput bool, out io.Writer) error {
	record, err := normalizeUserDNSRecord(name, recordType, value)
	if err != nil {
		return err
	}
	for _, existing := range config.DNSRecords {
		if strings.EqualFold(strings.TrimSuffix(existing.Name, "."), record.Name) {
			return fmt.Errorf("DNS record %s already exists", record.Name)
		}
	}
	oldConfig := config
	config.DNSRecords = append(config.DNSRecords, record)
	if err := validateComposedConfig(config); err != nil {
		return err
	}
	pending := withoutDNSDeletion(resolved.PendingDNSDeletions, record.Name, record.Type)
	if err := saveDNSConfigAndPending(siteDir, oldConfig, config, pending); err != nil {
		return err
	}
	if jsonOutput {
		return writeCLIJSON(out, record)
	}
	fmt.Fprintf(out, "DNS record added: %s %s %s\n", record.Name, record.Type, record.Value)
	return nil
}

func withoutDNSDeletion(deletions []model.DNSDeletion, name, recordType string) []model.DNSDeletion {
	name = normalizeDNSName(name)
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	result := make([]model.DNSDeletion, 0, len(deletions))
	for _, deletion := range deletions {
		if normalizeDNSName(deletion.Name) == name && strings.ToUpper(strings.TrimSpace(deletion.Type)) == recordType {
			continue
		}
		result = append(result, deletion)
	}
	return result
}

func removeDNSRecord(siteDir string, config model.SiteConfig, resolved model.Site, name, recordType string, jsonOutput bool, out io.Writer) error {
	name = normalizeDNSName(name)
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	if name == "" || (recordType != "A" && recordType != "CNAME") {
		return errors.New("dns record remove requires --name and --type A|CNAME")
	}
	index := -1
	for i, record := range config.DNSRecords {
		if normalizeDNSName(record.Name) == name && strings.ToUpper(record.Type) == recordType {
			if index != -1 {
				return fmt.Errorf("multiple user DNS records match %s %s", name, recordType)
			}
			index = i
		}
	}
	if index == -1 {
		return fmt.Errorf("no user DNS record matches %s %s", name, recordType)
	}
	removed := config.DNSRecords[index]
	oldConfig := config
	oldConfig.DNSRecords = append([]model.UserDNSRecord(nil), config.DNSRecords...)
	config.DNSRecords = append(config.DNSRecords[:index], config.DNSRecords[index+1:]...)
	if err := validateComposedConfig(config); err != nil {
		return err
	}
	pending := append([]model.DNSDeletion(nil), resolved.PendingDNSDeletions...)
	pending = append(pending, model.DNSDeletion{Name: name, Type: recordType})
	if err := saveDNSConfigAndPending(siteDir, oldConfig, config, pending); err != nil {
		return err
	}
	if jsonOutput {
		return writeCLIJSON(out, removed)
	}
	fmt.Fprintf(out, "DNS record removed: %s %s\n", name, recordType)
	return nil
}

func normalizeUserDNSRecord(name, recordType, value string) (model.UserDNSRecord, error) {
	name = normalizeDNSName(name)
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if name == "" {
		return model.UserDNSRecord{}, errors.New("dns record add requires --name")
	}
	if recordType != "A" && recordType != "CNAME" {
		return model.UserDNSRecord{}, errors.New("dns record --type must be A or CNAME")
	}
	if value == "" {
		return model.UserDNSRecord{}, errors.New("dns record add requires --value")
	}
	if recordType == "A" {
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil {
			return model.UserDNSRecord{}, fmt.Errorf("A record value %q is not an IPv4 address", value)
		}
		value = ip.To4().String()
	}
	return model.UserDNSRecord{Name: name, Type: recordType, Value: value}, nil
}

func normalizeDNSName(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

func saveDNSConfigAndPending(siteDir string, oldConfig, newConfig model.SiteConfig, pending []model.DNSDeletion) error {
	if err := site.SaveConfig(siteDir, newConfig); err != nil {
		return err
	}
	_, resolved, err := loadComposedConfig(siteDir)
	if err != nil {
		_ = site.SaveConfig(siteDir, oldConfig)
		return err
	}
	if err := site.SavePendingDNSDeletions(siteDir, resolved, pending); err != nil {
		if restoreErr := site.SaveConfig(siteDir, oldConfig); restoreErr != nil {
			return fmt.Errorf("save DNS runtime state: %w; restore site configuration: %v", err, restoreErr)
		}
		return err
	}
	return nil
}
