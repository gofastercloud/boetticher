package streamdeck

import (
	"context"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"strings"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

var (
	green = color.RGBA{R: 23, G: 107, B: 58, A: 255}
	red   = color.RGBA{R: 155, G: 28, B: 28, A: 255}
	black = color.RGBA{A: 255}
	white = color.RGBA{R: 255, G: 255, B: 255, A: 255}
)

type Deck interface {
	ButtonCount() int
	ImageSize() int
	SetBrightness(context.Context, uint8) error
	ProcessImage(image.Image) ([]byte, error)
	SetButton(context.Context, int, []byte) error
	Close(context.Context) error
}

func ProxmoxHosts(resources []Resource) []Resource {
	hosts := make([]Resource, 0, len(resources))
	for _, resource := range resources {
		switch strings.ToLower(resource.Kind) {
		case "node", "host", "proxmox-host", "pve":
			hosts = append(hosts, resource)
		}
	}
	for i := 1; i < len(hosts); i++ {
		for j := i; j > 0 && hostLess(hosts[j], hosts[j-1]); j-- {
			hosts[j], hosts[j-1] = hosts[j-1], hosts[j]
		}
	}
	return hosts
}

func hostLess(left, right Resource) bool {
	leftFolded, rightFolded := strings.ToLower(left.Name), strings.ToLower(right.Name)
	return leftFolded < rightFolded || (leftFolded == rightFolded && left.Name < right.Name)
}

func statusColor(status string, stale bool) color.Color {
	if stale {
		return red
	}
	switch strings.ToLower(status) {
	case "up", "online", "ok", "healthy", "running":
		return green
	default:
		return red
	}
}

func metricValue(value *float64) string {
	if value == nil {
		return "--"
	}
	return fmt.Sprintf("%.0f%%", *value)
}

func hostValue(resource Resource) string {
	return "C " + metricValue(resource.CPU) + " R " + metricValue(resource.Memory)
}

func tile(size int, title, value string, background color.Color) image.Image {
	if size < 1 {
		size = 72
	}
	result := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.Draw(result, result.Bounds(), &image.Uniform{C: background}, image.Point{}, draw.Src)
	face := basicfont.Face7x13
	drawCentered(result, face, truncate(title, 10), size/2-2*face.Metrics().Height.Ceil()/2)
	drawCentered(result, face, truncate(value, 10), size/2+face.Metrics().Height.Ceil()/2)
	return result
}

func drawCentered(dst *image.RGBA, face font.Face, text string, baseline int) {
	width := font.MeasureString(face, text).Ceil()
	x := (dst.Bounds().Dx() - width) / 2
	drawer := font.Drawer{Dst: dst, Src: image.NewUniform(white), Face: face, Dot: fixed.P(x, baseline+face.Metrics().Ascent.Ceil())}
	drawer.DrawString(text)
}

func truncate(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

func Render(ctx context.Context, deck Deck, state *State) error {
	if deck == nil {
		return fmt.Errorf("StreamDeck is unavailable")
	}
	size := deck.ImageSize()
	if size < 1 {
		size = 72
	}
	if state == nil {
		return renderAll(ctx, deck, size, func(int) (string, string, color.Color) {
			return "PULSE", "WAIT", red
		})
	}
	hosts := ProxmoxHosts(state.Resources)
	return renderAll(ctx, deck, size, func(index int) (string, string, color.Color) {
		if index >= len(hosts) {
			if index == 0 {
				return "PULSE", "NO HOSTS", red
			}
			return "", "", black
		}
		host := hosts[index]
		return host.Name, hostValue(host), statusColor(host.Status, state.Stale != "")
	})
}

func renderAll(ctx context.Context, deck Deck, size int, content func(int) (string, string, color.Color)) error {
	for index := 0; index < deck.ButtonCount(); index++ {
		title, value, background := content(index)
		image := tile(size, title, value, background)
		encoded, err := deck.ProcessImage(image)
		if err != nil {
			return fmt.Errorf("encode StreamDeck key %d: %w", index, err)
		}
		if err := deck.SetButton(ctx, index, encoded); err != nil {
			return fmt.Errorf("set StreamDeck key %d: %w", index, err)
		}
	}
	return nil
}
