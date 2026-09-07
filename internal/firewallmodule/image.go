package firewallmodule

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gofastercloud/boetticher/internal/pathguard"
)

const (
	OpenWrtVersion           = "25.12.5"
	OpenWrtImageBuilder      = "r33051-f5dae5ece4"
	OpenWrtImageBuilderURL   = "https://downloads.openwrt.org/releases/25.12.5/targets/x86/64/openwrt-imagebuilder-25.12.5-x86-64.Linux-x86_64.tar.zst"
	OpenWrtImageProfile      = "generic"
	OpenWrtImageArchitecture = "x86/64"
)

var OpenWrtPackages = []string{
	"uhttpd", "uhttpd-mod-ubus", "rpcd", "rpcd-mod-file", "rpcd-mod-iwinfo",
	"px5g-mbedtls", "ca-bundle", "firewall4", "nftables", "qemu-ga",
}

type Image struct {
	Path   string
	Name   string
	SHA256 string
}

type ImageSpec struct {
	CacheDir          string
	ManagementAddress string
	ManagementNetmask string
	ManagementGateway string
	ControllerAddress string
	PasswordHash      string
	BuilderScript     string
}

// EnsureImage reuses the deterministic cache filename and otherwise invokes
// the one purpose-built official ImageBuilder path. PasswordHash is already a
// crypt hash; it is streamed to the builder and never placed in argv.
func EnsureImage(ctx context.Context, spec ImageSpec) (Image, error) {
	if spec.CacheDir == "" || spec.ManagementAddress == "" || spec.ManagementNetmask == "" || spec.ManagementGateway == "" || spec.ControllerAddress == "" || spec.PasswordHash == "" || spec.BuilderScript == "" {
		return Image{}, errors.New("OpenWrt image cache, HOME address/network/gateway, Controller address, password hash, and builder script are required")
	}
	name := "openwrt-" + OpenWrtVersion + "-" + OpenWrtImageBuilder + "-x86-64.img"
	path := filepath.Join(spec.CacheDir, name)
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return Image{}, err
	}
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		return imageFromPath(path)
	} else if err != nil && !os.IsNotExist(err) {
		return Image{}, fmt.Errorf("inspect cached OpenWrt image: %w", err)
	}
	if err := pathguard.MkdirAll(spec.CacheDir, 0700); err != nil {
		return Image{}, fmt.Errorf("create OpenWrt image cache: %w", err)
	}
	command := exec.CommandContext(ctx, spec.BuilderScript, path, spec.ManagementAddress, spec.ManagementNetmask, spec.ManagementGateway, spec.ControllerAddress)
	command.Stdin = strings.NewReader(spec.PasswordHash + "\n")
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return Image{}, fmt.Errorf("build pinned OpenWrt image: %w", err)
	}
	return imageFromPath(path)
}

func imageFromPath(path string) (Image, error) {
	file, err := os.Open(path)
	if err != nil {
		return Image{}, fmt.Errorf("open OpenWrt image: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return Image{}, fmt.Errorf("hash OpenWrt image: %w", err)
	}
	return Image{Path: path, Name: filepath.Base(path), SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}
