package controllerstatus

import (
	"context"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"strings"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

const (
	StreamDeckKeyCount  = 15
	StreamDeckImageSize = 72
)

type KeyEvent struct {
	Index int
}

// KeyImage contains both the semantic content used by tests and the rendered
// image consumed by the device adapter.
type KeyImage struct {
	Image  image.Image
	Title  string
	Value  string
	Footer string
	State  State
}

type StreamDeck interface {
	SetKey(context.Context, int, KeyImage) error
	Clear(context.Context) error
	Events() <-chan KeyEvent
	Close() error
}

type StreamDeckFactory func(context.Context) (StreamDeck, error)

type StreamDeckView string

const (
	StreamDeckHome        StreamDeckView = "home"
	StreamDeckHostDetail  StreamDeckView = "host"
	StreamDeckGuestDetail StreamDeckView = "guest"
)

type StreamDeckRenderer struct{}

func (StreamDeckRenderer) Render(snapshot StatusSnapshot, telemetry ProxmoxSnapshot, operation *operationDisplay, view StreamDeckView, page, guestIndex int) []KeyImage {
	keys := make([]KeyImage, StreamDeckKeyCount)
	for index := range keys {
		keys[index] = blankDeckKey()
	}
	switch view {
	case StreamDeckHostDetail:
		return renderHostDetail(keys, snapshot, telemetry)
	case StreamDeckGuestDetail:
		return renderGuestDetail(keys, telemetry, guestIndex)
	default:
		return renderHome(keys, snapshot, telemetry, operation, page)
	}
}

func renderHome(keys []KeyImage, snapshot StatusSnapshot, telemetry ProxmoxSnapshot, operation *operationDisplay, page int) []KeyImage {
	hostValue := telemetry.Host.Node
	if hostValue == "" {
		hostValue = "—"
	}
	hostTitle, hostFooter, hostState := "PVE", stateLabel(snapshot.Host.State), snapshot.Host.State
	if operation != nil {
		hostTitle = strings.ToUpper(operation.event.Name)
		hostValue = fmt.Sprintf("STEP %d/%d", operation.event.CurrentStep, operation.event.totalSteps())
		hostFooter = "RUNNING"
		hostState = Checking
		if operation.result == Failed {
			hostFooter = "FAILED"
			hostState = Failed
		}
	}
	keys[0] = renderDeckKey(hostTitle, hostValue, hostFooter, hostState)
	keys[1] = renderDeckKey("CPU", formatPercent(telemetry.Host.CPUPercent, telemetry.FetchedAt.IsZero()), "HOST", telemetryState(telemetry))
	keys[2] = renderDeckKey("RAM", formatMemoryPair(telemetry.Host.MemoryUsed, telemetry.Host.MemoryTotal), telemetryAge(telemetry), telemetryState(telemetry))
	storage := preferredStorage(telemetry.Storage)
	if storage == nil {
		keys[3] = renderDeckKey("DATA", "—", "NO DATA", Off)
	} else {
		keys[3] = renderDeckKey("DATA", formatMemoryPair(storage.Used, storage.Total), fmt.Sprintf("%.0f%%", storage.Percent), Off)
	}
	netValue := "—"
	if snapshot.Internet.ThroughputAt.IsZero() {
		netValue = "UP"
	} else {
		netValue = fmt.Sprintf("%.0fM", snapshot.Internet.ThroughputMbps)
		if time.Since(snapshot.Internet.ThroughputAt) > time.Hour {
			netValue += "*"
		}
	}
	keys[4] = renderDeckKey("NET", netValue, stateLabel(snapshot.Internet.State), snapshot.Internet.State)

	pageCount := guestPageCount(len(telemetry.Guests))
	if page >= pageCount {
		page = 0
	}
	start := page * 8
	for slot := 0; slot < 8 && start+slot < len(telemetry.Guests); slot++ {
		guest := telemetry.Guests[start+slot]
		keys[5+slot] = renderGuestKey(guest)
	}
	keys[13] = renderDeckKey("PAGE", fmt.Sprintf("%d/%d", page+1, pageCount), "GUESTS", Off)
	keys[14] = renderDeckKey("REFRESH", "READ", "STATUS", Off)
	return keys
}

func renderHostDetail(keys []KeyImage, snapshot StatusSnapshot, telemetry ProxmoxSnapshot) []KeyImage {
	keys[0] = renderDeckKey("NODE", telemetry.Host.Node, "HOST", snapshot.Host.State)
	keys[1] = renderDeckKey("VERSION", shortVersion(telemetry.Host.Version), "PVE", Off)
	keys[2] = renderDeckKey("UPTIME", formatDuration(telemetry.Host.Uptime), telemetryAge(telemetry), telemetryState(telemetry))
	keys[3] = renderDeckKey("CPU", formatPercent(telemetry.Host.CPUPercent, telemetry.FetchedAt.IsZero()), "HOST", telemetryState(telemetry))
	keys[4] = renderDeckKey("RAM", formatMemoryPair(telemetry.Host.MemoryUsed, telemetry.Host.MemoryTotal), telemetryAge(telemetry), telemetryState(telemetry))
	storage := preferredStorage(telemetry.Storage)
	if storage != nil {
		keys[5] = renderDeckKey("DATA", formatMemoryPair(storage.Used, storage.Total), fmt.Sprintf("%.0f%%", storage.Percent), Off)
	}
	keys[6] = renderDeckKey("UPDATES", stateLabel(snapshot.HostUpdates.State), "HOST", snapshot.HostUpdates.State)
	keys[7] = renderDeckKey("REBOOT", rebootLabel(snapshot.HostUpdates), "HOST", snapshot.HostUpdates.State)
	keys[8] = renderDeckKey("FW", stateLabel(snapshot.Firewall.State), "MODULE", snapshot.Firewall.State)
	keys[9] = renderDeckKey("DHCP", stateLabel(snapshot.DHCPNTP.State), "MODULE", snapshot.DHCPNTP.State)
	keys[10] = renderDeckKey("DNS", stateLabel(snapshot.DNS.State), "MODULE", snapshot.DNS.State)
	keys[13] = renderDeckKey("BACK", "HOME", "NAV", Off)
	keys[14] = renderDeckKey("REFRESH", "READ", "STATUS", Off)
	return keys
}

func renderGuestDetail(keys []KeyImage, telemetry ProxmoxSnapshot, guestIndex int) []KeyImage {
	if guestIndex < 0 || guestIndex >= len(telemetry.Guests) {
		keys[0] = renderDeckKey("GUEST", "UNKNOWN", telemetryAge(telemetry), Attention)
	} else {
		guest := telemetry.Guests[guestIndex]
		state := guestState(guest)
		keys[0] = renderDeckKey("VMID", fmt.Sprintf("%d", guest.VMID), guest.Kind, state)
		keys[1] = renderDeckKey("NAME", guest.Name, guestStatus(guest), state)
		keys[2] = renderDeckKey("TYPE", strings.ToUpper(guest.Kind), guestStatus(guest), state)
		keys[3] = renderDeckKey("CPU", formatPercent(guest.CPUPercent, telemetry.Stale), "GUEST", state)
		keys[4] = renderDeckKey("RAM", formatMemoryPair(guest.MemoryUsed, guest.MemoryTotal), telemetryAge(telemetry), state)
		keys[5] = renderDeckKey("UPTIME", formatDuration(guest.Uptime), telemetryAge(telemetry), state)
	}
	keys[13] = renderDeckKey("BACK", "HOME", "NAV", Off)
	keys[14] = renderDeckKey("REFRESH", "READ", "STATUS", Off)
	return keys
}

func renderGuestKey(guest GuestStats) KeyImage {
	return renderDeckKey(fmt.Sprintf("%d %s", guest.VMID, guest.Name), strings.ToUpper(guest.Kind), guestStatus(guest), guestState(guest))
}

func guestState(guest GuestStats) State {
	switch strings.ToLower(strings.TrimSpace(guest.Status)) {
	case "running", "online", "up":
		return Healthy
	case "stopped", "offline":
		return Off
	case "error", "failed":
		return Failed
	default:
		return Attention
	}
}

func guestStatus(guest GuestStats) string {
	status := strings.ToUpper(strings.TrimSpace(guest.Status))
	if status == "" {
		return "UNKNOWN"
	}
	return status
}

func telemetryState(telemetry ProxmoxSnapshot) State {
	if telemetry.FetchedAt.IsZero() {
		return Checking
	}
	if telemetry.Stale {
		return Attention
	}
	return Healthy
}

func telemetryAge(telemetry ProxmoxSnapshot) string {
	if telemetry.FetchedAt.IsZero() {
		return "NO DATA"
	}
	if telemetry.Stale {
		return "STALE"
	}
	return "HOST"
}

func stateLabel(state State) string {
	switch state {
	case Healthy:
		return "OK"
	case Attention:
		return "WARN"
	case Failed:
		return "FAIL"
	case Checking:
		return "CHECK"
	case Off:
		return "OFF"
	default:
		return "UNKNOWN"
	}
}

func rebootLabel(component Component) string {
	if strings.Contains(strings.ToLower(component.Detail), "reboot") {
		return "REQUIRED"
	}
	return "OK"
}

func preferredStorage(storage []StorageStats) *StorageStats {
	for index := range storage {
		if storage[index].Name == "boetticher-data" {
			return &storage[index]
		}
	}
	if len(storage) > 0 {
		return &storage[0]
	}
	return nil
}

func guestPageCount(count int) int {
	if count <= 0 {
		return 1
	}
	return (count + 7) / 8
}

func shortVersion(version string) string {
	version = strings.TrimSpace(version)
	if index := strings.LastIndex(version, "/"); index >= 0 {
		version = version[index+1:]
	}
	return version
}

func formatPercent(value float64, missing bool) string {
	if missing {
		return "—"
	}
	return fmt.Sprintf("%.0f%%", value)
}

func formatMemoryPair(used, total uint64) string {
	if total == 0 {
		if used == 0 {
			return "—"
		}
		return formatBytes(used)
	}
	return formatBytes(used) + "/" + formatBytes(total)
}

func formatBytes(value uint64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%dB", value)
	}
	valueFloat := float64(value)
	units := []string{"K", "M", "G", "T", "P"}
	for _, suffix := range units {
		valueFloat /= unit
		if valueFloat < unit {
			return fmt.Sprintf("%.1f%s", valueFloat, suffix)
		}
	}
	return fmt.Sprintf("%.1fE", valueFloat)
}

func formatDuration(value time.Duration) string {
	if value <= 0 {
		return "—"
	}
	days := value / (24 * time.Hour)
	hours := value % (24 * time.Hour) / time.Hour
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	minutes := value % time.Hour / time.Minute
	return fmt.Sprintf("%dh %dm", hours, minutes)
}

func renderDeckKey(title, value, footer string, state State) KeyImage {
	return KeyImage{Image: drawDeckImage(title, value, footer, state), Title: title, Value: value, Footer: footer, State: state}
}

func blankDeckKey() KeyImage {
	return KeyImage{Image: image.NewRGBA(image.Rect(0, 0, StreamDeckImageSize, StreamDeckImageSize)), State: Off}
}

func drawDeckImage(title, value, footer string, state State) image.Image {
	canvas := image.NewRGBA(image.Rect(0, 0, StreamDeckImageSize, StreamDeckImageSize))
	background := color.RGBA{R: 18, G: 28, B: 38, A: 255}
	draw.Draw(canvas, canvas.Bounds(), &image.Uniform{C: background}, image.Point{}, draw.Src)
	accent := deckStateColor(state)
	draw.Draw(canvas, image.Rect(0, 0, StreamDeckImageSize, 4), &image.Uniform{C: accent}, image.Point{}, draw.Src)
	face := basicfont.Face7x13
	drawDeckText(canvas, face, truncateDeckText(strings.ToUpper(title), 10), 12)
	drawDeckText(canvas, face, truncateDeckText(value, 10), 33)
	drawDeckText(canvas, face, truncateDeckText(strings.ToUpper(footer), 10), 56)
	return canvas
}

func deckStateColor(state State) color.Color {
	switch state {
	case Healthy:
		return color.RGBA{R: 66, G: 205, B: 139, A: 255}
	case Attention:
		return color.RGBA{R: 244, G: 188, B: 83, A: 255}
	case Failed:
		return color.RGBA{R: 255, G: 105, B: 118, A: 255}
	case Checking:
		return color.RGBA{R: 101, G: 156, B: 183, A: 255}
	default:
		return color.RGBA{R: 68, G: 78, B: 88, A: 255}
	}
}

func drawDeckText(dst *image.RGBA, face font.Face, text string, baseline int) {
	width := font.MeasureString(face, text).Ceil()
	x := (dst.Bounds().Dx() - width) / 2
	drawer := font.Drawer{Dst: dst, Src: image.NewUniform(color.White), Face: face, Dot: fixed.P(x, baseline)}
	drawer.DrawString(text)
}

func truncateDeckText(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
