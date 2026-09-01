package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gofastercloud/boetticher/internal/bifrost"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if filepath.Base(os.Args[0]) == "boetticher-litellm-model-capabilities" {
		if len(args) != 1 {
			return errors.New("usage: boetticher-litellm-model-capabilities MODEL_ALIAS")
		}
		return printLocalCapabilities(args[0])
	}
	if len(args) == 0 {
		return errors.New("usage: boetticher-bifrost serve|model-capabilities")
	}
	fs := flag.NewFlagSet("boetticher-bifrost "+args[0], flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", bifrost.DefaultConfigPath, "Bifrost configuration path")
	switch args[0] {
	case "serve":
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return errors.New("usage: boetticher-bifrost serve [--config PATH]")
		}
		config, err := bifrost.LoadConfig(*configPath)
		if err != nil {
			return err
		}
		router, err := bifrost.NewRouter(config, os.Getenv(bifrost.DefaultCredentialDirEnv))
		if err != nil {
			return err
		}
		server := &http.Server{Addr: config.Listen, Handler: router, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 125 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		go func() {
			<-ctx.Done()
			_ = server.Shutdown(context.Background())
		}()
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("Bifrost server: %w", err)
		}
		return nil
	case "model-capabilities":
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 1 {
			return errors.New("usage: boetticher-bifrost model-capabilities [--config PATH] MODEL_ALIAS")
		}
		return printCapabilities(*configPath, fs.Arg(0))
	default:
		return fmt.Errorf("unknown Bifrost command %q", args[0])
	}
}

func printLocalCapabilities(alias string) error {
	if alias == "" {
		return errors.New("model alias is required")
	}
	request, err := http.NewRequest(http.MethodGet, "http://"+bifrost.DefaultListen+"/internal/model-capabilities/"+url.PathEscape(alias), nil)
	if err != nil {
		return errors.New("create local Bifrost capabilities request")
	}
	client := &http.Client{Timeout: 125 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("local Bifrost capabilities endpoint is unavailable")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, bifrost.MaxResponseBytes+1))
	if err != nil || len(data) > bifrost.MaxResponseBytes || response.StatusCode != http.StatusOK {
		return errors.New("local Bifrost capabilities response is unavailable")
	}
	_, err = os.Stdout.Write(data)
	if err == nil && (len(data) == 0 || data[len(data)-1] != '\n') {
		_, err = os.Stdout.Write([]byte{'\n'})
	}
	return err
}

func printCapabilities(configPath, alias string) error {
	config, err := bifrost.LoadConfig(configPath)
	if err != nil {
		return err
	}
	router, err := bifrost.NewRouter(config, os.Getenv(bifrost.DefaultCredentialDirEnv))
	if err != nil {
		return err
	}
	capabilities, err := router.ModelCapabilities(context.Background(), alias)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(capabilities)
}
