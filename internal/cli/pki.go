package cli

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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

func runPKI(args []string, out io.Writer) error {
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
	if err := pki.ValidateClientName(name); err != nil {
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

func exportClient(runtimeDir, output string, out io.Writer) error {
	key, err := pathguard.ReadFile(filepath.Join(runtimeDir, "client.key.pem"))
	if err != nil {
		return fmt.Errorf("read client private key: %w", err)
	}
	cert, err := pathguard.ReadFile(filepath.Join(runtimeDir, "chain.crt.pem"))
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

func revokeClient(siteDir, runtimeDir, name string, out io.Writer) error {
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

func runPKITrust(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("pki trust export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	siteDir := fs.String("site", ".", "private site repository directory")
	output := fs.String("output", "-", "output path, or - for stdout")
	format := fs.String("format", "pem", "output format: pem or apple")
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
	var content []byte
	switch *format {
	case "pem":
		content = []byte(authority.RootCertPEM + authority.IssuingCertPEM)
	case "apple":
		content, err = appleTrustProfile(authority.RootCertPEM)
		if err != nil {
			return fmt.Errorf("create Apple trust profile: %w", err)
		}
	default:
		return fmt.Errorf("unsupported trust export format %q", *format)
	}
	if *output == "-" {
		_, err = out.Write(content)
		return err
	}
	if err := writePublic(*output, content); err != nil {
		return err
	}
	fmt.Fprintf(out, "Exported trust profile (%s): %s\n", *format, *output)
	return nil
}

func appleTrustProfile(rootPEM string) ([]byte, error) {
	block, rest := pem.Decode([]byte(rootPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("root certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse root certificate: %w", err)
	}
	if !certificate.IsCA {
		return nil, errors.New("root certificate is not a CA")
	}
	digest := sha256.Sum256(certificate.Raw)
	profileUUID := appleUUID(digest[:])
	payloadDigest := sha256.Sum256(append(append([]byte(nil), digest[:]...), []byte("payload")...))
	payloadUUID := appleUUID(payloadDigest[:])
	encoded := base64.StdEncoding.EncodeToString(certificate.Raw)
	commonName := certificate.Subject.CommonName
	if commonName == "" {
		commonName = "Boetticher Root CA"
	}
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n")
	b.WriteString("<key>PayloadContent</key>\n<array>\n<dict>\n")
	appleXMLString(&b, "PayloadCertificateFileName", "string", "boetticher-root-ca.cer")
	appleXMLString(&b, "PayloadContent", "data", encoded)
	appleXMLString(&b, "PayloadDescription", "string", "Trust the Boetticher private root certificate")
	appleXMLString(&b, "PayloadDisplayName", "string", commonName)
	appleXMLString(&b, "PayloadIdentifier", "string", "com.gofastercloud.boetticher.trust.root")
	appleXMLString(&b, "PayloadOrganization", "string", "Boetticher")
	appleXMLString(&b, "PayloadType", "string", "com.apple.security.root")
	appleXMLString(&b, "PayloadUUID", "string", payloadUUID)
	appleXMLString(&b, "PayloadVersion", "integer", "1")
	b.WriteString("</dict>\n</array>\n")
	appleXMLString(&b, "PayloadDescription", "string", "Boetticher private trust profile")
	appleXMLString(&b, "PayloadDisplayName", "string", "Boetticher private trust")
	appleXMLString(&b, "PayloadIdentifier", "string", "com.gofastercloud.boetticher.trust")
	appleXMLString(&b, "PayloadOrganization", "string", "Boetticher")
	appleXMLString(&b, "PayloadRemovalDisallowed", "true", "")
	appleXMLString(&b, "PayloadScope", "string", "System")
	appleXMLString(&b, "PayloadType", "string", "Configuration")
	appleXMLString(&b, "PayloadUUID", "string", profileUUID)
	appleXMLString(&b, "PayloadVersion", "integer", "1")
	b.WriteString("</dict>\n</plist>\n")
	return []byte(b.String()), nil
}

func appleXMLString(b *strings.Builder, key, kind, value string) {
	b.WriteString("<key>")
	_ = xml.EscapeText(b, []byte(key))
	b.WriteString("</key>\n")
	if kind == "true" || kind == "false" {
		b.WriteString("<" + kind + "/>\n")
		return
	}
	b.WriteString("<" + kind + ">")
	if kind == "string" {
		_ = xml.EscapeText(b, []byte(value))
	} else {
		b.WriteString(value)
	}
	b.WriteString("</" + kind + ">\n")
}

func appleUUID(data []byte) string {
	hex := fmt.Sprintf("%x", data)
	return strings.ToUpper(hex[:8] + "-" + hex[8:12] + "-" + hex[12:16] + "-" + hex[16:20] + "-" + hex[20:32])
}
