package streamdeck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const ConfigPath = "/etc/boetticher/streamdeck.json"

const (
	DefaultVendorID  uint16 = 0x0fd9
	DefaultProductID uint16 = 0x006d
	DefaultModel            = "Stream Deck MK.2"
)

type Config struct {
	PulseURL          string `json:"pulse_url"`
	VendorID          uint16 `json:"vendor_id"`
	ProductID         uint16 `json:"product_id"`
	Model             string `json:"model"`
	Serial            string `json:"serial,omitempty"`
	ClientCertificate string `json:"client_certificate"`
	ClientKey         string `json:"client_key"`
	CACertificate     string `json:"ca_certificate"`
}

func LoadConfig(reader io.Reader) (Config, error) {
	var config Config
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode StreamDeck configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Config{}, errors.New("StreamDeck configuration contains trailing data")
		}
		return Config{}, fmt.Errorf("decode StreamDeck configuration tail: %w", err)
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.PulseURL) == "" {
		return errors.New("StreamDeck configuration requires pulse_url")
	}
	if c.VendorID == 0 || c.ProductID == 0 || strings.TrimSpace(c.Model) == "" {
		return errors.New("StreamDeck configuration requires vendor_id, product_id, and model")
	}
	if c.VendorID != DefaultVendorID || c.ProductID != DefaultProductID || c.Model != DefaultModel {
		return fmt.Errorf("unsupported StreamDeck identity %04x:%04x %q", c.VendorID, c.ProductID, c.Model)
	}
	parsed, err := url.Parse(c.PulseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("StreamDeck pulse_url must be an HTTPS origin without query or fragment")
	}
	for name, value := range map[string]string{
		"client_certificate": c.ClientCertificate,
		"client_key":         c.ClientKey,
		"ca_certificate":     c.CACertificate,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("StreamDeck configuration requires %s", name)
		}
	}
	return nil
}
