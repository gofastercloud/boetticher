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
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
)

const (
	StreamDeckKeyCount        = 15
	StreamDeckImageSize       = 72
	streamDeckTextWidth       = StreamDeckImageSize - 8
	streamDeckMarqueeInterval = 750 * time.Millisecond
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
	// ImageKey captures time-varying rendering such as a hostname marquee so
	// the USB worker can skip unchanged tiles without suppressing animation.
	ImageKey string
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

var streamDeckFont = loadStreamDeckFont()

func loadStreamDeckFont() font.Face {
	parsed, err := opentype.Parse(goregular.TTF)
	if err != nil {
		return basicfont.Face7x13
	}
	face, err := opentype.NewFace(parsed, &opentype.FaceOptions{Size: 8.5, DPI: 72, Hinting: font.HintingFull})
	if err != nil {
		return basicfont.Face7x13
	}
	return face
}

func (StreamDeckRenderer) Render(snapshot StatusSnapshot, telemetry ProxmoxSnapshot, operation *operationDisplay, view StreamDeckView, page, guestIndex int) []KeyImage {
	return (StreamDeckRenderer{}).RenderAt(snapshot, telemetry, operation, view, page, guestIndex, time.Now())
}

func (StreamDeckRenderer) RenderAt(snapshot StatusSnapshot, telemetry ProxmoxSnapshot, operation *operationDisplay, view StreamDeckView, page, guestIndex int, now time.Time) []KeyImage {
	keys := make([]KeyImage, StreamDeckKeyCount)
	for index := range keys {
		keys[index] = blankDeckKey()
	}
	switch view {
	case StreamDeckHostDetail:
		return renderHostDetail(keys, snapshot, telemetry, now)
	case StreamDeckGuestDetail:
		return renderGuestDetail(keys, telemetry, guestIndex, now)
	default:
		return renderHome(keys, snapshot, telemetry, operation, page, now)
	}
}

func renderHome(keys []KeyImage, snapshot StatusSnapshot, telemetry ProxmoxSnapshot, operation *operationDisplay, page int, now time.Time) []KeyImage {
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
	keys[0] = renderDeckKeyAt(hostTitle, hostValue, hostFooter, hostState, now, true)
	keys[1] = renderDeckKey("CPU", formatPercent(telemetry.Host.CPUPercent, telemetry.FetchedAt.IsZero()), "HOST", telemetryState(telemetry))
	keys[2] = renderDeckKey("RAM", formatMemoryPair(telemetry.Host.MemoryUsed, telemetry.Host.MemoryTotal), telemetryAge(telemetry), telemetryState(telemetry))
	storage := preferredStorage(telemetry.Storage)
	if storage == nil {
		keys[3] = renderDeckKey("DATA", "—", "NO DATA", telemetryState(telemetry))
	} else {
		keys[3] = renderDeckKey("DATA", formatMemoryPair(storage.Used, storage.Total), fmt.Sprintf("%.0f%%", storage.Percent), telemetryState(telemetry))
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
	start := page * 5
	for slot := 0; slot < 5 && start+slot < len(telemetry.Guests); slot++ {
		guest := telemetry.Guests[start+slot]
		keys[5+slot] = renderGuestKeyAt(guest, now)
	}
	keys[10] = renderDeckKey("FW", stateLabel(snapshot.Firewall.State), "MODULE", snapshot.Firewall.State)
	keys[11] = renderDeckKey("VPN", stateLabel(snapshot.VPN.State), "MODULE", snapshot.VPN.State)
	keys[12] = renderDeckKey("TAILNET", stateLabel(snapshot.Tailnet.State), "MODULE", snapshot.Tailnet.State)
	keys[13] = renderDeckKey("SCROLL", fmt.Sprintf("%d/%d", page+1, pageCount), "GUESTS", Off)
	keys[14] = renderDeckKey("REFRESH", "READ", "STATUS", Off)
	return keys
}

func renderHostDetail(keys []KeyImage, snapshot StatusSnapshot, telemetry ProxmoxSnapshot, now time.Time) []KeyImage {
	keys[0] = renderDeckKeyAt("NODE", telemetry.Host.Node, "HOST", snapshot.Host.State, now, true)
	keys[1] = renderDeckKey("VERSION", shortVersion(telemetry.Host.Version), "PVE", Off)
	keys[2] = renderDeckKey("UPTIME", formatDuration(telemetry.Host.Uptime), telemetryAge(telemetry), telemetryState(telemetry))
	keys[3] = renderDeckKey("CPU", formatPercent(telemetry.Host.CPUPercent, telemetry.FetchedAt.IsZero()), "HOST", telemetryState(telemetry))
	keys[4] = renderDeckKey("RAM", formatMemoryPair(telemetry.Host.MemoryUsed, telemetry.Host.MemoryTotal), telemetryAge(telemetry), telemetryState(telemetry))
	storage := preferredStorage(telemetry.Storage)
	if storage != nil {
		keys[5] = renderDeckKey("DATA", formatMemoryPair(storage.Used, storage.Total), fmt.Sprintf("%.0f%%", storage.Percent), telemetryState(telemetry))
	}
	keys[6] = renderDeckKey("UPDATES", stateLabel(snapshot.HostUpdates.State), "HOST", snapshot.HostUpdates.State)
	keys[7] = renderDeckKey("REBOOT", rebootLabel(snapshot.HostUpdates), "HOST", snapshot.HostUpdates.State)
	keys[8] = renderDeckKey("FW", stateLabel(snapshot.Firewall.State), "MODULE", snapshot.Firewall.State)
	keys[9] = renderDeckKey("DHCP", stateLabel(snapshot.DHCPNTP.State), "MODULE", snapshot.DHCPNTP.State)
	keys[10] = renderDeckKey("TAILNET", stateLabel(snapshot.Tailnet.State), "MODULE", snapshot.Tailnet.State)
	keys[11] = renderDeckKey("DNS", stateLabel(snapshot.DNS.State), "MODULE", snapshot.DNS.State)
	keys[13] = renderDeckKey("BACK", "HOME", "NAV", Off)
	keys[14] = renderDeckKey("REFRESH", "READ", "STATUS", Off)
	return keys
}

func renderGuestDetail(keys []KeyImage, telemetry ProxmoxSnapshot, guestIndex int, now time.Time) []KeyImage {
	if guestIndex < 0 || guestIndex >= len(telemetry.Guests) {
		keys[0] = renderDeckKey("GUEST", "UNKNOWN", telemetryAge(telemetry), Attention)
	} else {
		guest := telemetry.Guests[guestIndex]
		state := guestState(guest)
		keys[0] = renderDeckKeyAt(guestIdentity(guest), guest.Name, guestStatus(guest), state, now, true)
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

func renderGuestKeyAt(guest GuestStats, now time.Time) KeyImage {
	return renderDeckKeyAt(guestIdentity(guest), guest.Name, guestStatus(guest), guestState(guest), now, true)
}

func guestIdentity(guest GuestStats) string {
	kind := "VM"
	if strings.EqualFold(strings.TrimSpace(guest.Kind), "lxc") || strings.EqualFold(strings.TrimSpace(guest.Kind), "container") {
		kind = "CT"
	}
	return fmt.Sprintf("%s%d", kind, guest.VMID)
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
	return (count + 4) / 5
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
	return renderDeckKeyAt(title, value, footer, state, time.Now(), false)
}

func renderDeckKeyAt(title, value, footer string, state State, now time.Time, marqueeValue bool) KeyImage {
	imageKey := value
	if marqueeValue {
		imageKey = marqueeDeckText(streamDeckFont, value, streamDeckTextWidth, now)
	}
	return KeyImage{Image: drawDeckImage(title, value, footer, state, now, marqueeValue), Title: title, Value: value, Footer: footer, State: state, ImageKey: imageKey}
}

func blankDeckKey() KeyImage {
	return KeyImage{Image: image.NewRGBA(image.Rect(0, 0, StreamDeckImageSize, StreamDeckImageSize)), State: Off}
}

func drawDeckImage(title, value, footer string, state State, now time.Time, marqueeValue bool) image.Image {
	canvas := image.NewRGBA(image.Rect(0, 0, StreamDeckImageSize, StreamDeckImageSize))
	background := color.RGBA{R: 18, G: 28, B: 38, A: 255}
	draw.Draw(canvas, canvas.Bounds(), &image.Uniform{C: background}, image.Point{}, draw.Src)
	accent := deckStateColor(state)
	draw.Draw(canvas, image.Rect(0, 0, StreamDeckImageSize, 4), &image.Uniform{C: accent}, image.Point{}, draw.Src)
	face := streamDeckFont
	drawDeckText(canvas, face, strings.ToUpper(title), 12, false, now)
	drawDeckText(canvas, face, value, 33, marqueeValue, now)
	drawDeckText(canvas, face, strings.ToUpper(footer), 56, false, now)
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

func drawDeckText(dst *image.RGBA, face font.Face, text string, baseline int, marquee bool, now time.Time) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	maxWidth := dst.Bounds().Dx() - 8
	if marquee {
		text = marqueeDeckText(face, text, maxWidth, now)
	} else if font.MeasureString(face, text).Ceil() > maxWidth {
		text = fitDeckText(face, text, maxWidth)
	}
	drawDeckTextAt(dst, face, text, baseline)
}

func fitDeckText(face font.Face, text string, maxWidth int) string {
	text = strings.TrimSpace(text)
	if font.MeasureString(face, text).Ceil() <= maxWidth {
		return text
	}
	const ellipsis = "…"
	runes := []rune(text)
	for len(runes) > 0 {
		candidate := string(runes) + ellipsis
		if font.MeasureString(face, candidate).Ceil() <= maxWidth {
			return candidate
		}
		runes = runes[:len(runes)-1]
	}
	return ellipsis
}

func needsDeckMarquee(text string) bool {
	return font.MeasureString(streamDeckFont, strings.TrimSpace(text)).Ceil() > streamDeckTextWidth
}

func marqueeDeckText(face font.Face, text string, maxWidth int, now time.Time) string {
	text = strings.TrimSpace(text)
	if font.MeasureString(face, text).Ceil() <= maxWidth {
		return text
	}
	base := []rune(text + "   " + text)
	if len(base) == 0 {
		return text
	}
	offset := int((now.UnixMilli() / 750) % int64(len(base)))
	window := make([]rune, 0, len(base))
	for index := 0; index < len(base); index++ {
		candidate := append(window, base[(offset+index)%len(base)])
		if font.MeasureString(face, string(candidate)).Ceil() > maxWidth {
			break
		}
		window = candidate
	}
	return strings.TrimSpace(string(window))
}

func drawDeckTextAt(dst *image.RGBA, face font.Face, text string, baseline int) {
	width := font.MeasureString(face, text).Ceil()
	x := (dst.Bounds().Dx() - width) / 2
	drawer := font.Drawer{Dst: dst, Src: image.NewUniform(color.White), Face: face, Dot: fixed.P(x, baseline)}
	drawer.DrawString(text)
}
