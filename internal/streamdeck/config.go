package streamdeck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const ConfigPath = "/etc/boetticher/streamdeck.json"

const (
	DefaultVendorID  uint16 = 0x0fd9
	DefaultProductID uint16 = 0x006d
	DefaultModel            = "Stream Deck MK.2"
)

type Config struct {
	VendorID  uint16 `json:"vendor_id"`
	ProductID uint16 `json:"product_id"`
	Model     string `json:"model"`
	Serial    string `json:"serial,omitempty"`
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
	if c.VendorID == 0 || c.ProductID == 0 || strings.TrimSpace(c.Model) == "" {
		return errors.New("StreamDeck configuration requires vendor_id, product_id, and model")
	}
	if c.VendorID != DefaultVendorID || c.ProductID != DefaultProductID || c.Model != DefaultModel {
		return fmt.Errorf("unsupported StreamDeck identity %04x:%04x %q", c.VendorID, c.ProductID, c.Model)
	}
	return nil
}
