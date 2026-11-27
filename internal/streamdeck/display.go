package streamdeck

import (
	"context"
	"image"
	"image/color"

	"golang.org/x/image/font"
	"golang.org/x/image/math/fixed"
)

var (
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
