package controllerstatus

import (
	"context"
	"math"
	"time"
)

const PixelCount = 8

type Pixel struct {
	R          uint8 `json:"r"`
	G          uint8 `json:"g"`
	B          uint8 `json:"b"`
	Brightness uint8 `json:"brightness"`
}

type Driver interface {
	Show(context.Context, []Pixel) error
	Clear(context.Context) error
	Close() error
}

type Renderer struct {
	MaxBrightness uint8
}

func NewRenderer(brightness float64) Renderer {
	if brightness <= 0 {
		brightness = 0.3
	}
	if brightness > 1 {
		brightness = 1
	}
	maximum := uint8(math.Round(brightness * 31))
	if maximum == 0 {
		maximum = 1
	}
	return Renderer{MaxBrightness: maximum}
}

func (r Renderer) Frame(snapshot StatusSnapshot, now time.Time) []Pixel {
	components := []Component{
		snapshot.Controller,
		snapshot.Host,
		snapshot.Firewall,
		snapshot.DNS,
		snapshot.DHCP,
		snapshot.Internet.Component,
		snapshot.Configuration,
		snapshot.RebootRequired,
	}
	frame := make([]Pixel, PixelCount)
	for index, component := range components {
		frame[index] = r.componentPixel(component.State, now, index)
	}
	return frame
}

func (r Renderer) OperationFrame(event OperationEvent, now time.Time) []Pixel {
	frame := make([]Pixel, PixelCount)
	total := event.totalSteps()
	if total <= 0 {
		total = 1
	}
	current := event.CurrentStep
	if current < 0 {
		current = 0
	}
	if current > total {
		current = total
	}
	completed := current * PixelCount / total
	for index := 0; index < completed && index < PixelCount; index++ {
		frame[index] = r.colourPixel(0, 180, 35, r.MaxBrightness)
	}
	if current < total && completed < PixelCount {
		frame[completed] = r.componentPixel(Checking, now, completed)
	}
	return frame
}

func (r Renderer) FailureFrame(event OperationEvent, now time.Time) []Pixel {
	frame := r.OperationFrame(event, now)
	total := event.totalSteps()
	if total <= 0 {
		total = 1
	}
	failed := event.CurrentStep * PixelCount / total
	if failed >= PixelCount {
		failed = PixelCount - 1
	}
	if now.UnixMilli()/350%2 == 0 {
		frame[failed] = r.componentPixel(Failed, now, failed)
	}
	return frame
}

func (r Renderer) colourPixel(red, green, blue, brightness uint8) Pixel {
	return Pixel{R: red, G: green, B: blue, Brightness: brightness}
}

func (r Renderer) componentPixel(state State, now time.Time, index int) Pixel {
	var red, green, blue uint8
	switch state {
	case Healthy:
		red, green, blue = 0, 180, 35
	case Attention:
		red, green, blue = 220, 95, 0
	case Failed:
		red, green, blue = 220, 0, 0
	case Checking:
		red, green, blue = 0, 45, 220
	case Off:
		return Pixel{}
	default:
		return r.componentPixel(Checking, now, index)
	}

	brightness := r.MaxBrightness
	seconds := float64(now.UnixNano()) / float64(time.Second)
	switch state {
	case Healthy, Attention:
		phase := (math.Sin(2*math.Pi*seconds/3) + 1) / 2
		brightness = uint8(math.Max(1, math.Round(float64(r.MaxBrightness)*(0.3+0.7*phase))))
	case Checking:
		phase := (math.Sin(2*math.Pi*seconds/1.2+float64(index)/3) + 1) / 2
		brightness = uint8(math.Max(1, math.Round(float64(r.MaxBrightness)*(0.35+0.65*phase))))
	case Failed:
		if now.UnixMilli()/350%2 == 1 {
			brightness = 0
		}
	}
	return r.colourPixel(red, green, blue, brightness)
}
