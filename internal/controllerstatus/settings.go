package controllerstatus

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath        = "/etc/boetticher/controller.yml"
	DefaultSocketPath        = "/run/boetticher/status.sock"
	DefaultDriverPath        = "/opt/boetticher/current/controller/roles/controller-baseline/files/boetticher-blinkt-driver"
	DefaultHostSpeedtestPath = "/usr/local/libexec/boetticher-host-speedtest"
	DefaultRebootRequired    = "/var/run/reboot-required"
	DefaultInterval          = 30 * time.Second
	DefaultPingPeriod        = 60 * time.Second
	DefaultThroughputPeriod  = time.Hour
	DefaultTelemetryPeriod   = 15 * time.Second
	DefaultHealthyMbps       = 500.0
	DefaultStreamDeckSerial  = ""
)

type StreamDeckConfig struct {
	Serial string
}

type Settings struct {
	ConfigPath           string
	SocketPath           string
	DriverPath           string
	RebootRequiredPath   string
	GPIOChip             int
	Interval             time.Duration
	PingInterval         time.Duration
	ThroughputInterval   time.Duration
	TelemetryInterval    time.Duration
	HealthyMbps          float64
	BlinktEnabled        bool
	Brightness           float64
	StreamDeckEnabled    bool
	StreamDeckBrightness float64
	StreamDeckSerial     string
}

func DefaultSettings() Settings {
	return Settings{
		ConfigPath:           DefaultConfigPath,
		SocketPath:           DefaultSocketPath,
		DriverPath:           DefaultDriverPath,
		RebootRequiredPath:   DefaultRebootRequired,
		GPIOChip:             0,
		Interval:             DefaultInterval,
		PingInterval:         DefaultPingPeriod,
		ThroughputInterval:   DefaultThroughputPeriod,
		TelemetryInterval:    DefaultTelemetryPeriod,
		HealthyMbps:          DefaultHealthyMbps,
		BlinktEnabled:        true,
		Brightness:           0.3,
		StreamDeckEnabled:    true,
		StreamDeckBrightness: 0.5,
		StreamDeckSerial:     DefaultStreamDeckSerial,
	}
}

type rawSettings struct {
	Blinkt *struct {
		Enabled  *bool `yaml:"enabled"`
		GPIOChip *int  `yaml:"gpiochip"`
	} `yaml:"blinkt"`
	Status *struct {
		Interval     string `yaml:"interval"`
		PingInterval string `yaml:"ping_interval"`
		Internet     struct {
			ThroughputInterval string  `yaml:"throughput_interval"`
			HealthyMbps        float64 `yaml:"healthy_mbps"`
		} `yaml:"internet"`
		Blinkt struct {
			Enabled    *bool    `yaml:"enabled"`
			Brightness *float64 `yaml:"brightness"`
			GPIOChip   *int     `yaml:"gpiochip"`
		} `yaml:"blinkt"`
		StreamDeck struct {
			Enabled           *bool    `yaml:"enabled"`
			Brightness        *float64 `yaml:"brightness"`
			TelemetryInterval string   `yaml:"telemetry_interval"`
			Serial            string   `yaml:"serial"`
		} `yaml:"streamdeck"`
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
	if raw.Status.PingInterval != "" {
		settings.PingInterval, err = time.ParseDuration(raw.Status.PingInterval)
		if err != nil || settings.PingInterval <= 0 {
			return settings, fmt.Errorf("status ping_interval must be a positive duration")
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
	if raw.Status.Blinkt.Enabled != nil {
		settings.BlinktEnabled = *raw.Status.Blinkt.Enabled
	}
	if raw.Status.Blinkt.Brightness != nil {
		settings.Brightness = *raw.Status.Blinkt.Brightness
	}
	if raw.Status.Blinkt.GPIOChip != nil {
		settings.GPIOChip = *raw.Status.Blinkt.GPIOChip
	}
	if raw.Status.StreamDeck.Enabled != nil {
		settings.StreamDeckEnabled = *raw.Status.StreamDeck.Enabled
	}
	if raw.Status.StreamDeck.Brightness != nil {
		settings.StreamDeckBrightness = *raw.Status.StreamDeck.Brightness
	}
	if raw.Status.StreamDeck.TelemetryInterval != "" {
		settings.TelemetryInterval, err = time.ParseDuration(raw.Status.StreamDeck.TelemetryInterval)
		if err != nil || settings.TelemetryInterval <= 0 {
			return settings, fmt.Errorf("status streamdeck telemetry_interval must be a positive duration")
		}
	}
	if raw.Status.StreamDeck.Serial != "" {
		settings.StreamDeckSerial = raw.Status.StreamDeck.Serial
	}
	if settings.GPIOChip < 0 {
		return settings, fmt.Errorf("status gpiochip must not be negative")
	}
	if settings.Brightness <= 0 || settings.Brightness > 1 {
		return settings, fmt.Errorf("status brightness must be greater than 0 and at most 1")
	}
	if settings.StreamDeckBrightness <= 0 || settings.StreamDeckBrightness > 1 {
		return settings, fmt.Errorf("status streamdeck brightness must be greater than 0 and at most 1")
	}
	return settings, nil
}
