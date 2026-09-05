package streamdeck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gofastercloud/boetticher/internal/companion"
	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/opentype"
)

type ConsoleTile struct{ Label, Value, State, Action, Target string }

var consoleLabels = []string{"PI", "LAB LINK", "GATEWAY", "DNS", "PROXMOX", "PULSE", "AGENT", "DISPLAYS"}

func ConsoleTiles(s companion.Snapshot) []ConsoleTile {
	tiles := make([]ConsoleTile, 15)
	items := s.Items
	if s.View != "pi" && len(s.LEDs) == 8 {
		items = s.LEDs
	}
	for i, item := range items {
		if i >= 8 {
			break
		}
		tiles[i] = ConsoleTile{consoleLabels[i], item.Value, item.Status, "select", item.ID}
		if item.ID == "airvpn" {
			tiles[i].Label = "AIRVPN"
		}
		if item.ID == "tailnet-router" {
			tiles[i].Label = "TAILNET"
		}
		if tiles[i].Value == "" {
			tiles[i].Value = item.Status
		}
	}
	if s.View == "resources" {
		for i := 0; i < 8; i++ {
			tiles[i] = ConsoleTile{}
			index := s.Page*8 + i
			if index < len(s.Resources) {
				r := s.Resources[index]
				value := r.Status
				if r.CPU != nil {
					value = fmt.Sprintf("CPU %.0f%%", *r.CPU)
				}
				tiles[i] = ConsoleTile{r.Name, value, r.Status, "select", "resource:" + r.ID}
			}
		}
	}
	tiles[8] = ConsoleTile{"RESOURCES", "Browse", "", "select", "resources"}
	tiles[9] = ConsoleTile{"REFRESH", "Read again", "", "refresh", ""}
	for i, label := range []string{"HOME", "BACK", "PREVIOUS", "NEXT", "DIM/WAKE"} {
		tiles[10+i] = ConsoleTile{Label: label, Action: []string{"home", "back", "previous", "next", "dim"}[i]}
	}
	return tiles
}
func sendControl(ctx context.Context, client *http.Client, path, action, target string) error {
	data, _ := json.Marshal(map[string]string{"action": action, "target": target})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://companion"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 204 {
		return fmt.Errorf("local action HTTP %d", res.StatusCode)
	}
	return nil
}
func consoleImage(size int, tile ConsoleTile, small, large font.Face) image.Image {
	canvas := image.NewRGBA(image.Rect(0, 0, size, size))
	background := color.RGBA{R: 18, G: 28, B: 38, A: 255}
	draw.Draw(canvas, canvas.Bounds(), &image.Uniform{C: background}, image.Point{}, draw.Src)
	accent := color.RGBA{R: 101, G: 156, B: 183, A: 255}
	switch tile.State {
	case companion.Healthy:
		accent = color.RGBA{R: 66, G: 205, B: 139, A: 255}
	case companion.Warning:
		accent = color.RGBA{R: 244, G: 188, B: 83, A: 255}
	case companion.Failure:
		accent = color.RGBA{R: 255, G: 105, B: 118, A: 255}
	case companion.Disabled:
		accent = color.RGBA{R: 68, G: 78, B: 88, A: 255}
	}
	draw.Draw(canvas, image.Rect(0, 0, size, 4), &image.Uniform{C: accent}, image.Point{}, draw.Src)
	value := tile.Value
	if value == "" {
		value = "•"
	}
	if len(value) > 8 {
		value = truncate(value, 8)
	}
	drawCentered(canvas, small, truncate(strings.ToUpper(tile.Label), 10), 10)
	drawCentered(canvas, large, value, 29)
	label := strings.ToUpper(tile.State)
	if tile.State == companion.Healthy {
		label = "OK"
	}
	if tile.State == "" {
		label = "PRESS"
	}
	drawCentered(canvas, small, label, 55)
	return canvas
}

func RunConsole(ctx context.Context, config Config, open DeckOpener) error {
	parsed, err := opentype.Parse(goregular.TTF)
	if err != nil {
		return err
	}
	small, err := opentype.NewFace(parsed, &opentype.FaceOptions{Size: 9, DPI: 72, Hinting: font.HintingFull})
	if err != nil {
		return err
	}
	defer small.Close()
	large, err := opentype.NewFace(parsed, &opentype.FaceOptions{Size: 15, DPI: 72, Hinting: font.HintingFull})
	if err != nil {
		return err
	}
	defer large.Close()
	client := companion.LocalClient()
	buttons := make(chan int, 16)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var deck Deck
	var retryAt time.Time
	var snapshot companion.Snapshot
	var last []ConsoleTile
	var lastBrightness uint8 = 255
	defer func() {
		if deck != nil {
			_ = deck.Close(context.Background())
		}
	}()
	for {
		if deck == nil && !time.Now().Before(retryAt) {
			candidate, err := open(ctx, config)
			if err == nil && candidate != nil {
				interactive, ok := candidate.(interface {
					SetHandler(func(context.Context, int) error)
				})
				if !ok {
					_ = candidate.Close(ctx)
					return fmt.Errorf("StreamDeck driver has no button handler")
				}
				if candidate.ButtonCount() != 15 {
					_ = candidate.Close(ctx)
					return fmt.Errorf("Companion requires the supported 15-key StreamDeck")
				}
				interactive.SetHandler(func(_ context.Context, index int) error {
					select {
					case buttons <- index:
					default:
					}
					return nil
				})
				deck = candidate
				last = nil
				lastBrightness = 255
				slog.Info("StreamDeck connected")
			} else {
				retryAt = time.Now().Add(3 * time.Second)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case index := <-buttons:
			if index >= 0 && index < len(last) && last[index].Action != "" {
				_ = sendControl(ctx, client, "/action", last[index].Action, last[index].Target)
			}
		case <-ticker.C:
			next, err := companion.ReadSnapshot(ctx, client)
			if err != nil {
				next = companion.Snapshot{Items: make([]companion.Item, 8), Brightness: "normal"}
				for i := range next.Items {
					next.Items[i] = companion.Item{Status: companion.Waiting, Value: "NO DATA"}
				}
			}
			snapshot = next
			if deck == nil {
				continue
			}
			brightness := uint8(20)
			if snapshot.Brightness == "dim" {
				brightness = 5
			}
			if snapshot.Brightness == "blank" {
				brightness = 0
			}
			failed := false
			if brightness != lastBrightness {
				if deck.SetBrightness(ctx, brightness) != nil {
					failed = true
				} else {
					lastBrightness = brightness
				}
			}
			tiles := ConsoleTiles(snapshot)
			for i, tile := range tiles {
				if len(last) == 15 && tile == last[i] {
					continue
				}
				img := consoleImage(deck.ImageSize(), tile, small, large)
				data, err := deck.ProcessImage(img)
				if err != nil || deck.SetButton(ctx, i, data) != nil {
					failed = true
					break
				}
			}
			if failed {
				_ = deck.Close(context.Background())
				deck = nil
				last = nil
				retryAt = time.Now().Add(3 * time.Second)
				continue
			}
			last = tiles
			_ = sendControl(ctx, client, "/heartbeat", "streamdeck", "")
		}
	}
}
