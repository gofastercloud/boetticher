package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofastercloud/boetticher/internal/model"
	"github.com/gofastercloud/boetticher/internal/pathguard"
	"github.com/gofastercloud/boetticher/internal/pki"
	"github.com/gofastercloud/boetticher/internal/site"
	"gopkg.in/yaml.v3"
)

type clientCertificateMetadata struct {
	Name   string `yaml:"name"`
	Serial string `yaml:"serial"`
}

func runPKI(args []string, out interface{ Write([]byte) (int, error) }) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: boetticher pki client create|export|revoke NAME; boetticher pki trust export")
	}
	subcommand := args[0]
	if subcommand == "trust" && args[1] == "export" {
		return runPKITrust(args[2:], out)
	}
	if subcommand != "client" {
		return fmt.Errorf("unknown pki command %q", subcommand)
	}
	if len(args) < 3 {
		return fmt.Errorf("client name is required")
	}
	command, name := args[1], args[2]
	fs := flag.NewFlagSet("pki client", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	output := fs.String("output", "", "export output path")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	if err := fs.Parse(args[3:]); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	runtimeDir := filepath.Join(site.RuntimeDir(s), "pki", name)
	switch command {
	case "create":
		authority, err := site.LoadAuthority(*siteDir, s, *ageIdentity)
		if err != nil {
			return err
		}
		certificate, err := pki.IssueClient(authority, name, s.Network.Domain, time.Now().UTC())
		if err != nil {
			return err
		}
		if err := os.MkdirAll(runtimeDir, 0700); err != nil {
			return err
		}
		if err := writePrivate(filepath.Join(runtimeDir, "client.key.pem"), []byte(certificate.KeyPEM)); err != nil {
			return err
		}
		if err := writePublic(filepath.Join(runtimeDir, "client.crt.pem"), []byte(certificate.CertPEM)); err != nil {
			return err
		}
		if err := writePublic(filepath.Join(runtimeDir, "chain.crt.pem"), []byte(certificate.ChainPEM)); err != nil {
			return err
		}
		metadata := fmt.Sprintf("name: %s\nfingerprint: %s\nserial: %s\ncreated_at: %s\n", name, certificate.Fingerprint, certificate.Serial, time.Now().UTC().Format(time.RFC3339))
		if err := writePublic(filepath.Join(*siteDir, "generated", "pki", name+".yaml"), []byte(metadata)); err != nil {
			return err
		}
		if s.BootstrapAddress != "" {
			if err := rebuildPortal(*siteDir, s); err != nil {
				return err
			}
		}
		fmt.Fprintf(out, "Created client certificate %s\nPrivate key: %s\nCertificate: %s\n", name, filepath.Join(runtimeDir, "client.key.pem"), filepath.Join(runtimeDir, "client.crt.pem"))
		return nil
	case "export":
		return exportClient(runtimeDir, *output, out)
	case "revoke":
		return revokeClient(*siteDir, runtimeDir, name, out)
	default:
		return fmt.Errorf("unknown pki client command %q", command)
	}
}

func exportClient(runtimeDir, output string, out interface{ Write([]byte) (int, error) }) error {
	key, err := os.ReadFile(filepath.Join(runtimeDir, "client.key.pem"))
	if err != nil {
		return fmt.Errorf("read client private key: %w", err)
	}
	cert, err := os.ReadFile(filepath.Join(runtimeDir, "chain.crt.pem"))
	if err != nil {
		return fmt.Errorf("read client certificate chain: %w", err)
	}
	if output == "" {
		output = filepath.Join(runtimeDir, "client-bundle.pem")
	}
	if output == "-" {
		return fmt.Errorf("refusing to write a client private key to stdout; choose a file output")
	}
	if err := writePrivate(output, append(key, cert...)); err != nil {
		return err
	}
	fmt.Fprintf(out, "Exported client PEM bundle: %s\n", output)
	return nil
}

func revokeClient(siteDir, runtimeDir, name string, out interface{ Write([]byte) (int, error) }) error {
	if err := pki.ValidateClientName(name); err != nil {
		return err
	}
	serial, err := loadClientMetadataSerial(siteDir, name)
	if err != nil {
		return err
	}
	if serial == "" {
		certPEM, readErr := pathguard.ReadFile(filepath.Join(runtimeDir, "client.crt.pem"))
		if readErr != nil {
			return fmt.Errorf("read issued client certificate for revocation: %w", readErr)
		}
		serial, err = pki.CertificateSerial(string(certPEM))
		if err != nil {
			return fmt.Errorf("identify issued client certificate for revocation: %w", err)
		}
	}
	revocation := fmt.Sprintf("name: %s\nserial: %s\nstatus: revoked\nrevoked_at: %s\n", name, serial, time.Now().UTC().Format(time.RFC3339))
	path := filepath.Join(siteDir, "generated", "pki", "revoked", name+".yaml")
	if err := writePublic(path, []byte(revocation)); err != nil {
		return err
	}
	if s, err := site.Load(siteDir); err == nil && s.BootstrapAddress != "" {
		if err := rebuildPortal(siteDir, s); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "Recorded client revocation: %s\n", name)
	return nil
}

func loadClientMetadataSerial(siteDir, name string) (string, error) {
	path := filepath.Join(siteDir, "generated", "pki", name+".yaml")
	data, err := pathguard.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read client certificate metadata: %w", err)
	}
	var metadata clientCertificateMetadata
	if err := yaml.Unmarshal(data, &metadata); err != nil {
		return "", fmt.Errorf("parse client certificate metadata: %w", err)
	}
	if metadata.Name != name {
		return "", fmt.Errorf("client certificate metadata name %q does not match %q", metadata.Name, name)
	}
	if metadata.Serial == "" {
		return "", nil
	}
	serial, err := pki.ParseSerial(metadata.Serial)
	if err != nil {
		return "", fmt.Errorf("client certificate metadata serial: %w", err)
	}
	return serial.Text(16), nil
}

func runPKITrust(args []string, out interface{ Write([]byte) (int, error) }) error {
	fs := flag.NewFlagSet("pki trust export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	output := fs.String("output", "-", "output path, or - for stdout")
	ageIdentity := fs.String("age-identity", model.DefaultAgeIdentity, "external Age identity path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := site.Load(*siteDir)
	if err != nil {
		return err
	}
	authority, err := site.LoadAuthority(*siteDir, s, *ageIdentity)
	if err != nil {
		return err
	}
	content := []byte(authority.RootCertPEM + authority.IssuingCertPEM)
	if *output == "-" {
		_, err = out.Write(content)
		return err
	}
	if err := writePublic(*output, content); err != nil {
		return err
	}
	fmt.Fprintf(out, "Exported trust chain: %s\n", *output)
	return nil
}
