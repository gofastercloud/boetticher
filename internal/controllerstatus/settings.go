package controllerstatus

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath       = "/etc/boetticher/controller.yml"
	DefaultSocketPath       = "/run/boetticher/status.sock"
	DefaultDriverPath       = "/opt/boetticher/current/controller/roles/controller-baseline/files/boetticher-blinkt-driver"
	DefaultRebootRequired   = "/var/run/reboot-required"
	DefaultInterval         = 30 * time.Second
	DefaultThroughputPeriod = 10 * time.Minute
	DefaultHealthyMbps      = 500.0
	DefaultTransferBytes    = 10 << 20
)

type Settings struct {
	ConfigPath         string
	SocketPath         string
	DriverPath         string
	RebootRequiredPath string
	GPIOChip           int
	Interval           time.Duration
	ThroughputInterval time.Duration
	HealthyMbps        float64
	TransferBytes      int64
	BlinktEnabled      bool
	Brightness         float64
}

func DefaultSettings() Settings {
	return Settings{
		ConfigPath:         DefaultConfigPath,
		SocketPath:         DefaultSocketPath,
		DriverPath:         DefaultDriverPath,
		RebootRequiredPath: DefaultRebootRequired,
		GPIOChip:           0,
		Interval:           DefaultInterval,
		ThroughputInterval: DefaultThroughputPeriod,
		HealthyMbps:        DefaultHealthyMbps,
		TransferBytes:      DefaultTransferBytes,
		BlinktEnabled:      true,
		Brightness:         0.3,
	}
}

type rawSettings struct {
	Blinkt *struct {
		Enabled  *bool `yaml:"enabled"`
		GPIOChip *int  `yaml:"gpiochip"`
	} `yaml:"blinkt"`
	Status *struct {
		Interval string `yaml:"interval"`
		Internet struct {
			ThroughputInterval string  `yaml:"throughput_interval"`
			HealthyMbps        float64 `yaml:"healthy_mbps"`
			TransferMB         int64   `yaml:"transfer_mb"`
		} `yaml:"internet"`
		Blinkt struct {
			Enabled    *bool    `yaml:"enabled"`
			Brightness *float64 `yaml:"brightness"`
			GPIOChip   *int     `yaml:"gpiochip"`
		} `yaml:"blinkt"`
	} `yaml:"status"`
}

func LoadSettings(path string) (Settings, error) {
	settings := DefaultSettings()
	if path != "" {
		settings.ConfigPath = path
	}
	data, err := os.ReadFile(settings.ConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		return settings, nil
	}
	if err != nil {
		return settings, fmt.Errorf("read Controller status configuration: %w", err)
	}
	var raw rawSettings
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return settings, fmt.Errorf("decode Controller status configuration: %w", err)
	}
	if raw.Blinkt != nil {
		if raw.Blinkt.Enabled != nil {
			settings.BlinktEnabled = *raw.Blinkt.Enabled
		}
		if raw.Blinkt.GPIOChip != nil {
			settings.GPIOChip = *raw.Blinkt.GPIOChip
		}
	}
	if raw.Status == nil {
		return settings, nil
	}
	if raw.Status.Interval != "" {
		settings.Interval, err = time.ParseDuration(raw.Status.Interval)
		if err != nil || settings.Interval <= 0 {
			return settings, fmt.Errorf("status interval must be a positive duration")
		}
	}
	if raw.Status.Internet.ThroughputInterval != "" {
		settings.ThroughputInterval, err = time.ParseDuration(raw.Status.Internet.ThroughputInterval)
		if err != nil || settings.ThroughputInterval <= 0 {
			return settings, fmt.Errorf("status throughput_interval must be a positive duration")
		}
	}
	if raw.Status.Internet.HealthyMbps > 0 {
		settings.HealthyMbps = raw.Status.Internet.HealthyMbps
	}
	if raw.Status.Internet.TransferMB > 0 {
		settings.TransferBytes = raw.Status.Internet.TransferMB * 1024 * 1024
	}
	if raw.Status.Blinkt.Enabled != nil {
		settings.BlinktEnabled = *raw.Status.Blinkt.Enabled
	}
	if raw.Status.Blinkt.Brightness != nil {
		settings.Brightness = *raw.Status.Blinkt.Brightness
	}
	if raw.Status.Blinkt.GPIOChip != nil {
		settings.GPIOChip = *raw.Status.Blinkt.GPIOChip
	}
	if settings.GPIOChip < 0 {
		return settings, fmt.Errorf("status gpiochip must not be negative")
	}
	if settings.Brightness <= 0 || settings.Brightness > 1 {
		return settings, fmt.Errorf("status brightness must be greater than 0 and at most 1")
	}
	return settings, nil
}
