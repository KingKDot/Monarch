package web

import (
	"bytes"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"math"
	mrand "math/rand"
	"strings"
	"sync"
	"time"

	"github.com/golang/freetype/truetype"
	"github.com/wenlng/go-captcha/v2/base/option"
	"github.com/wenlng/go-captcha/v2/click"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/goregular"
)

type clickCaptchaStore struct {
	mu    sync.Mutex
	items map[string]clickCaptchaItem

	ttl time.Duration

	capt click.Captcha
}

type clickCaptchaItem struct {
	expiresAt  time.Time
	verifyDots map[int]*click.Dot
	verifyLen  int
	masterPNG  []byte
	thumbPNG   []byte
}

type clickPoint struct {
	X int `json:"x"`
	Y int `json:"y"`
}

func newClickCaptchaStore() (*clickCaptchaStore, error) {
	fontRegular, err := truetype.Parse(goregular.TTF)
	if err != nil {
		return nil, err
	}
	fontBold, err := truetype.Parse(gobold.TTF)
	if err != nil {
		return nil, err
	}

	backgrounds := []image.Image{
		makeNoiseBackground(300, 220),
		makeNoiseBackground(300, 220),
		makeNoiseBackground(300, 220),
	}

	chars := strings.Split("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", "")
	if len(chars) < 10 {
		return nil, errors.New("captcha chars too short")
	}

	builder := click.NewBuilder(
		click.WithImageSize(option.Size{Width: 300, Height: 220}),
		click.WithRangeThumbImageSize(option.Size{Width: 160, Height: 50}),
		click.WithRangeLen(option.RangeVal{Min: 6, Max: 7}),
		click.WithRangeVerifyLen(option.RangeVal{Min: 2, Max: 4}),
	)
	builder.SetResources(
		click.WithChars(chars),
		click.WithFonts([]*truetype.Font{fontRegular, fontBold}),
		click.WithBackgrounds(backgrounds),
	)

	return &clickCaptchaStore{
		items: map[string]clickCaptchaItem{},
		ttl:   3 * time.Minute,
		capt:  builder.Make(),
	}, nil
}

func (s *clickCaptchaStore) purgeLocked(now time.Time) {
	for k, v := range s.items {
		if now.After(v.expiresAt) {
			delete(s.items, k)
		}
	}
}

func (s *clickCaptchaStore) New(now time.Time) (id string, masterPNG []byte, thumbPNG []byte, verifyLen int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(now)

	data, err := s.capt.Generate()
	if err != nil {
		return "", nil, nil, 0, err
	}
	verifyDots := data.GetData()
	verifyLen = len(verifyDots)
	if verifyLen < 1 {
		return "", nil, nil, 0, errors.New("captcha generate failed")
	}

	masterImg := data.GetMasterImage().Get()
	var mb bytes.Buffer
	if err := png.Encode(&mb, masterImg); err != nil {
		return "", nil, nil, 0, err
	}
	masterPNG = mb.Bytes()

	thumbPNG, err = data.GetThumbImage().ToBytes()
	if err != nil {
		return "", nil, nil, 0, err
	}

	// 16 bytes hex = 32 chars.
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		return "", nil, nil, 0, err
	}
	id = hex.EncodeToString(b)

	s.items[id] = clickCaptchaItem{
		expiresAt:  now.Add(s.ttl),
		verifyDots: verifyDots,
		verifyLen:  verifyLen,
		masterPNG:  masterPNG,
		thumbPNG:   thumbPNG,
	}
	return id, masterPNG, thumbPNG, verifyLen, nil
}

func (s *clickCaptchaStore) GetMaster(id string, now time.Time) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(now)
	it, ok := s.items[id]
	if !ok {
		return nil, false
	}
	return it.masterPNG, true
}

func (s *clickCaptchaStore) GetThumb(id string, now time.Time) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(now)
	it, ok := s.items[id]
	if !ok {
		return nil, false
	}
	return it.thumbPNG, true
}

func (s *clickCaptchaStore) Verify(id string, solution string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(now)
	item, ok := s.items[id]
	if !ok {
		return false
	}
	// One-time use (even on failure we discard to reduce brute force value).
	delete(s.items, id)

	var pts []clickPoint
	if err := json.Unmarshal([]byte(solution), &pts); err != nil {
		return false
	}
	if len(pts) != item.verifyLen {
		return false
	}

	padding := 10
	for i := 0; i < item.verifyLen; i++ {
		dot := item.verifyDots[i]
		if dot == nil {
			return false
		}
		p := pts[i]
		if !click.Validate(p.X, p.Y, dot.X, dot.Y, dot.Width, dot.Height, padding) {
			return false
		}
	}
	return true
}

func makeNoiseBackground(w, h int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	// Use a random-ish seed from crypto/rand when available.
	seed := uint64(time.Now().UnixNano())
	var sb [8]byte
	if _, err := crand.Read(sb[:]); err == nil {
		seed ^= uint64(sb[0])<<56 | uint64(sb[1])<<48 | uint64(sb[2])<<40 | uint64(sb[3])<<32 | uint64(sb[4])<<24 | uint64(sb[5])<<16 | uint64(sb[6])<<8 | uint64(sb[7])
	}
	r := mrand.New(mrand.NewSource(int64(seed)))

	// Dark-ish base + gentle noise so characters remain readable.
	baseR := float64(r.Intn(30) + 10)
	baseG := float64(r.Intn(30) + 10)
	baseB := float64(r.Intn(30) + 10)

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			n := float64(r.Intn(35))
			fx := float64(x) / math.Max(1, float64(w-1))
			fy := float64(y) / math.Max(1, float64(h-1))
			img.SetRGBA(x, y, color.RGBA{
				R: uint8(clamp(baseR+n+fx*10, 0, 255)),
				G: uint8(clamp(baseG+n+fy*10, 0, 255)),
				B: uint8(clamp(baseB+n+(fx+fy)*5, 0, 255)),
				A: 255,
			})
		}
	}
	return img
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
