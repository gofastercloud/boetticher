package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gofastercloud/boetticher/internal/controllerstatus"
)

func main() {
	configPath := flag.String("config", controllerstatus.DefaultConfigPath, "Controller configuration path")
	socketPath := flag.String("socket", controllerstatus.DefaultSocketPath, "local operation event socket")
	driverPath := flag.String("driver", controllerstatus.DefaultDriverPath, "local Blinkt driver path")
	chip := flag.Int("gpiochip", -1, "GPIO chip number (overrides Controller configuration)")
	flag.Parse()

	logger := log.New(os.Stderr, "boetticher-status: ", log.LstdFlags)
	settings, err := controllerstatus.LoadSettings(*configPath)
	if err != nil {
		logger.Printf("configuration warning: %v; using safe defaults", err)
	}
	settings.ConfigPath = *configPath
	settings.SocketPath = *socketPath
	settings.DriverPath = *driverPath
	if *chip >= 0 {
		settings.GPIOChip = *chip
	}
	var driver controllerstatus.Driver
	if settings.BlinktEnabled {
		driver, err = controllerstatus.NewProcessDriver("/usr/bin/python3", settings.DriverPath, settings.GPIOChip)
		if err != nil {
			logger.Printf("Blinkt unavailable; health checks continue: %v", err)
		}
	}
	daemon := controllerstatus.NewDaemon(settings, driver)
	daemon.Logger = logger
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := daemon.Run(ctx); err != nil {
		logger.Printf("daemon failed: %v", err)
		os.Exit(1)
	}
}
