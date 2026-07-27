package lib

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"math/big"
	mrand "math/rand"
	"sync"
	"time"
)

type ObfuscationConfig struct {
	MinPadding          int `json:"minPadding"`
	MaxPadding          int `json:"maxPadding"`
	MinDelayMs          int `json:"minDelayMs"`
	MaxDelayMs          int `json:"maxDelayMs"`
	FakeFrameIntervalMs int `json:"fakeFrameIntervalMs"`
	FakeFrameSizeMin    int `json:"fakeFrameSizeMin"`
	FakeFrameSizeMax    int `json:"fakeFrameSizeMax"`
}

func AddPadding(data []byte, minPad, maxPad int) []byte {
	if minPad <= 0 || maxPad <= 0 || maxPad < minPad {
		return data
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(maxPad-minPad+1)))
	padSize := int(n.Int64()) + minPad
	pad := make([]byte, padSize)
	rand.Read(pad)
	out := make([]byte, len(data)+padSize+4)
	copy(out, data)
	copy(out[len(data):], pad)
	binary.BigEndian.PutUint32(out[len(data)+padSize:], uint32(padSize))
	return out
}

func StripPadding(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return data, nil
	}
	padSize := int(binary.BigEndian.Uint32(data[len(data)-4:]))
	if padSize <= 0 || padSize > len(data)-4 {
		return data, nil
	}
	return data[:len(data)-4-padSize], nil
}

func BimodalDelay(minMs, maxMs int) time.Duration {
	if mrand.Float64() < 0.80 {
		return time.Duration(mrand.Intn(5)) * time.Millisecond
	}
	lo := max(minMs, 50)
	hi := max(maxMs, 200)
	if hi <= lo {
		return time.Duration(lo) * time.Millisecond
	}
	return time.Duration(mrand.Intn(hi-lo+1)+lo) * time.Millisecond
}

func UniformDelay(minMs, maxMs int) time.Duration {
	if maxMs <= minMs {
		return time.Duration(minMs) * time.Millisecond
	}
	return time.Duration(mrand.Intn(maxMs-minMs+1)+minMs) * time.Millisecond
}

type fakeFrameMsg struct {
	Type    string `json:"type"`
	Ts      int64  `json:"ts,omitempty"`
	Seq     int    `json:"seq,omitempty"`
	Bitrate int    `json:"bitrate,omitempty"`
	Buffer  int    `json:"bufferMs,omitempty"`
	Res     string `json:"resolution,omitempty"`
	FPS     int    `json:"fps,omitempty"`
	User    string `json:"user,omitempty"`
	Msg     string `json:"msg,omitempty"`
}

var fakeFrameTemplates = []func() fakeFrameMsg{
	func() fakeFrameMsg {
		return fakeFrameMsg{Type: "ping", Ts: time.Now().UnixMilli()}
	},
	func() fakeFrameMsg {
		return fakeFrameMsg{Type: "video_stats", Bitrate: 1500 + mrand.Intn(3000), Buffer: 500 + mrand.Intn(5000)}
	},
	func() fakeFrameMsg {
		return fakeFrameMsg{Type: "heartbeat", Seq: mrand.Intn(10000)}
	},
	func() fakeFrameMsg {
		res := []string{"720p", "1080p", "480p", "1440p"}
		return fakeFrameMsg{Type: "quality", Res: res[mrand.Intn(len(res))], FPS: 24 + mrand.Intn(7)}
	},
	func() fakeFrameMsg {
		users := []string{"viewer_831", "stream_fan", "user_42", "live_now", "chat_bot"}
		msgs := []string{"great stream!", "love this", "hello everyone", "nice quality", "buffering?"}
		return fakeFrameMsg{Type: "chat", User: users[mrand.Intn(len(users))], Msg: msgs[mrand.Intn(len(msgs))]}
	},
}

func GenerateFakePayload() []byte {
	tmpl := fakeFrameTemplates[mrand.Intn(len(fakeFrameTemplates))]
	msg := tmpl()
	data, _ := json.Marshal(msg)
	return data
}

type FakeFrameScheduler struct {
	ws       WSWriter
	config   ObfuscationConfig
	stopCh   chan struct{}
	stopped  bool
	mu       sync.Mutex
	bytesSent int64
}

type WSWriter interface {
	WriteMessage(messageType int, data []byte) error
}

func NewFakeFrameScheduler(ws WSWriter, config ObfuscationConfig) *FakeFrameScheduler {
	return &FakeFrameScheduler{
		ws:     ws,
		config: config,
		stopCh: make(chan struct{}),
	}
}

func (s *FakeFrameScheduler) Start() {
	go s.loop()
}

func (s *FakeFrameScheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.stopped {
		s.stopped = true
		close(s.stopCh)
	}
}

func (s *FakeFrameScheduler) BytesSent() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytesSent
}

func (s *FakeFrameScheduler) loop() {
	interval := time.Duration(s.config.FakeFrameIntervalMs) * time.Millisecond
	for {
		jitter := time.Duration(mrand.Intn(max(1, int(interval.Milliseconds()/4)))) * time.Millisecond
		select {
		case <-s.stopCh:
			return
		case <-time.After(interval + jitter):
			payload := GenerateFakePayload()
			err := s.ws.WriteMessage(2, payload)
			if err != nil {
				return
			}
			s.mu.Lock()
			s.bytesSent += int64(len(payload))
			s.mu.Unlock()
		}
	}
}
