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
	"time"

	"github.com/gofastercloud/boetticher/internal/pathguard"
)

const (
	OpenWrtVersion           = "25.12.5"
	OpenWrtImageBuilder      = "r33051-f5dae5ece4"
	OpenWrtImageBuilderURL   = "https://downloads.openwrt.org/releases/25.12.5/targets/x86/64/openwrt-imagebuilder-25.12.5-x86-64.Linux-x86_64.tar.zst"
	OpenWrtImageProfile      = "generic"
	OpenWrtImageArchitecture = "x86/64"
	OpenWrtImageContract     = "v8"
	ProviderTLSName          = "boetticher-firewall"
)

var OpenWrtPackages = []string{
	"uhttpd", "uhttpd-mod-ubus", "rpcd", "rpcd-mod-file", "rpcd-mod-iwinfo",
	"px5g-mbedtls", "ca-bundle", "firewall4", "nftables", "dnsmasq", "stubby", "qemu-ga", "wireguard-tools", "kmod-wireguard", "ip-full", "flock",
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
	path, err := prepareImagePath(spec)
	if err != nil {
		return Image{}, err
	}
	if cached, ok, err := cachedImage(path); err != nil || ok {
		return cached, err
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

// EnsureImageViaHost runs the pinned x86_64 ImageBuilder on the enrolled
// Proxmox Host. This is the supported route for an ARM64 Controller: the
// Controller streams only the password hash over strict SSH stdin and copies
// the resulting image back over the same Host identity binding.
func EnsureImageViaHost(ctx context.Context, host HostClient, spec ImageSpec) (image Image, retErr error) {
	path, err := prepareImagePath(spec)
	if err != nil {
		return Image{}, err
	}
	if cached, ok, err := cachedImage(path); err != nil || ok {
		return cached, err
	}
	prepare, err := host.Run(ctx, "set -eu; d=$(mktemp -d /var/tmp/boetticher-openwrt-build.XXXXXX); printf '%s\\n' '{\"version\":1,\"outer\":true}' >\"$d/.boetticher-build-owned\"; : >\"$d/.boetticher-build.lock\"; chmod 600 \"$d/.boetticher-build-owned\" \"$d/.boetticher-build.lock\"; printf '%s\\n' \"$d\"")
	if err != nil {
		return Image{}, fmt.Errorf("prepare OpenWrt build directory on Host: %w", err)
	}
	remote := strings.TrimSpace(string(prepare.Stdout))
	if remote == "" || strings.ContainsAny(remote, "\r\n\x00") || filepath.Dir(remote) != "/var/tmp" || !strings.HasPrefix(filepath.Base(remote), "boetticher-openwrt-build.") {
		return Image{}, errors.New("Host returned an unsafe OpenWrt build directory")
	}
	remoteScript := remote + "/build-openwrt-firewall.sh"
	remoteHelper := remote + "/build-temp.py"
	remoteImage := remote + "/output.img"
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, cleanupErr := host.Run(cleanupCtx, "case "+shellQuote(remote)+" in /var/tmp/boetticher-openwrt-build.*) exec 9>"+shellQuote(remote+"/.boetticher-build.lock")+"; flock -n 9; rm -rf -- "+shellQuote(remote)+";; *) exit 1;; esac"); cleanupErr != nil && retErr == nil {
			retErr = fmt.Errorf("cleanup OpenWrt Host build directory: %w", cleanupErr)
		}
	}()
	if err := host.Copy(ctx, spec.BuilderScript, remoteScript); err != nil {
		return Image{}, fmt.Errorf("copy pinned OpenWrt builder to Host: %w", err)
	}
	helper := filepath.Join(filepath.Dir(spec.BuilderScript), "build-temp.py")
	if err := host.Copy(ctx, helper, remoteHelper); err != nil {
		return Image{}, fmt.Errorf("copy build temporary helper to Host: %w", err)
	}
	command := "set -eu; exec 9>" + shellQuote(remote+"/.boetticher-build.lock") + "; flock -n 9; chmod 700 " + shellQuote(remoteScript) + " " + shellQuote(remoteHelper) + "; /bin/sh " + shellQuote(remoteScript) + " " + shellQuote(remoteImage) + " " + shellQuote(spec.ManagementAddress) + " " + shellQuote(spec.ManagementNetmask) + " " + shellQuote(spec.ManagementGateway) + " " + shellQuote(spec.ControllerAddress)
	result, err := host.RunWithStdin(ctx, command, strings.NewReader(spec.PasswordHash+"\n"))
	if err != nil {
		detail := strings.TrimSpace(string(result.Stderr))
		if detail == "" {
			detail = strings.TrimSpace(string(result.Stdout))
		}
		if detail != "" {
			return Image{}, fmt.Errorf("build pinned OpenWrt image on x86 Host: %w: %s", err, detail)
		}
		return Image{}, fmt.Errorf("build pinned OpenWrt image on x86 Host: %w", err)
	}
	temporary := path + ".tmp"
	if err := pathguard.ValidateNoSymlinkComponents(temporary); err != nil {
		return Image{}, err
	}
	if err := host.CopyFromHost(ctx, remoteImage, temporary); err != nil {
		return Image{}, fmt.Errorf("copy OpenWrt image from Host: %w", err)
	}
	image, err = imageFromPath(temporary)
	if err != nil {
		return Image{}, err
	}
	if err := pathguard.Rename(temporary, path); err != nil {
		return Image{}, fmt.Errorf("activate OpenWrt image cache: %w", err)
	}
	image.Path = path
	return image, nil
}

func prepareImagePath(spec ImageSpec) (string, error) {
	if spec.CacheDir == "" || spec.ManagementAddress == "" || spec.ManagementNetmask == "" || spec.ManagementGateway == "" || spec.ControllerAddress == "" || spec.PasswordHash == "" || spec.BuilderScript == "" {
		return "", errors.New("OpenWrt image cache, HOME address/network/gateway, Controller address, password hash, and builder script are required")
	}
	name := "openwrt-" + OpenWrtVersion + "-" + OpenWrtImageBuilder + "-" + OpenWrtImageContract + "-x86-64.img"
	path := filepath.Join(spec.CacheDir, name)
	if err := pathguard.ValidateNoSymlinkComponents(path); err != nil {
		return "", err
	}
	if err := pathguard.MkdirAll(spec.CacheDir, 0700); err != nil {
		return "", fmt.Errorf("create OpenWrt image cache: %w", err)
	}
	return path, nil
}

func cachedImage(path string) (Image, bool, error) {
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		image, imageErr := imageFromPath(path)
		return image, true, imageErr
	} else if err != nil && !os.IsNotExist(err) {
		return Image{}, false, fmt.Errorf("inspect cached OpenWrt image: %w", err)
	}
	return Image{}, false, nil
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
