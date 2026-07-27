package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/smartsni/dpi-evasion/lib"
)

type Config struct {
	Server         ServerConfig         `json:"server"`
	DomainFronting lib.FrontingConfig   `json:"domain_fronting"`
	Obfuscation    lib.ObfuscationConfig `json:"obfuscation"`
	Relay          RelayConfig          `json:"relay"`
	RateLimit      RateLimitConfig      `json:"rateLimit"`
	Auth           AuthConfig           `json:"auth"`
	ShadowTLS      lib.ShadowTLSConfig  `json:"shadowtls"`
}

type ServerConfig struct {
	Port    int    `json:"port"`
	Host    string `json:"host"`
	Domain  string `json:"domain"`
	CertPath string `json:"certPath"`
	KeyPath string `json:"keyPath"`
}

type RelayConfig struct {
	IdleTimeoutSec    int `json:"idleTimeoutSec"`
	MaxConnections    int `json:"maxConnections"`
	BufferSize        int `json:"bufferSize"`
	SessionRotationMin int `json:"sessionRotationMin"`
}

type RateLimitConfig struct {
	MaxPerIp  int `json:"maxPerIp"`
	WindowSec int `json:"windowSec"`
}

type AuthConfig struct {
	Enabled bool   `json:"enabled"`
	Secret  string `json:"secret"`
}

type RateLimiter struct {
	mu       sync.Mutex
	hits     map[string][]time.Time
	maxPerIp int
	window   time.Duration
}

func NewRateLimiter(cfg RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		hits:     make(map[string][]time.Time),
		maxPerIp: cfg.MaxPerIp,
		window:   time.Duration(cfg.WindowSec) * time.Second,
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)
	hits := rl.hits[ip]
	n := 0
	for _, t := range hits {
		if t.After(cutoff) {
			n++
		}
	}
	if n >= rl.maxPerIp {
		return false
	}
	rl.hits[ip] = append(rl.hits[ip], now)
	return true
}

func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)
	for ip, hits := range rl.hits {
		valid := hits[:0]
		for _, t := range hits {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.hits, ip)
		} else {
			rl.hits[ip] = valid
		}
	}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  65536,
	WriteBufferSize: 65536,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type RelayStats struct {
	mu              sync.Mutex
	activeConns     int
	totalBytesIn    int64
	totalBytesOut   int64
	totalConns      int64
	startTime       time.Time
}

var stats = &RelayStats{startTime: time.Now()}

func (s *RelayStats) AddConn() {
	s.mu.Lock()
	s.activeConns++
	s.totalConns++
	s.mu.Unlock()
}

func (s *RelayStats) RemoveConn() {
	s.mu.Lock()
	s.activeConns--
	s.mu.Unlock()
}

func (s *RelayStats) AddBytesIn(n int64) {
	s.mu.Lock()
	s.totalBytesIn += n
	s.mu.Unlock()
}

func (s *RelayStats) AddBytesOut(n int64) {
	s.mu.Lock()
	s.totalBytesOut += n
	s.mu.Unlock()
}

var (
	cfg       Config
	rateLimiter *RateLimiter
)

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.Server.Port == 0 {
		c.Server.Port = 443
	}
	if c.Server.Host == "" {
		c.Server.Host = "0.0.0.0"
	}
	if c.Relay.BufferSize == 0 {
		c.Relay.BufferSize = 65536
	}
	if c.Relay.IdleTimeoutSec == 0 {
		c.Relay.IdleTimeoutSec = 120
	}
	if c.Relay.SessionRotationMin == 0 {
		c.Relay.SessionRotationMin = 30
	}
	if c.RateLimit.MaxPerIp == 0 {
		c.RateLimit.MaxPerIp = 10
	}
	if c.RateLimit.WindowSec == 0 {
		c.RateLimit.WindowSec = 60
	}
	return &c, nil
}

func loadCerts(certPath, keyPath string) ([]byte, []byte, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read key: %w", err)
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert: %w", err)
	}
	return cert, key, nil
}

func coverHTML() []byte {
	return []byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FastCDN - Global Content Delivery Network</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>&#9889;</text></svg>">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0e1a;color:#e2e8f0;line-height:1.6}
.hero{text-align:center;padding:100px 20px 60px;background:linear-gradient(135deg,#0a0e1a 0%,#1a1f3a 50%,#0a0e1a 100%)}
.hero h1{font-size:3.2rem;background:linear-gradient(135deg,#00d4ff,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:16px}
.hero .tagline{font-size:1.2rem;color:#94a3b8;max-width:600px;margin:0 auto 32px}
.hero .stats{display:flex;justify-content:center;gap:48px;margin-top:40px;flex-wrap:wrap}
.hero .stat{text-align:center}
.hero .stat .num{font-size:2rem;font-weight:700;color:#00d4ff}
.hero .stat .label{font-size:0.85rem;color:#64748b;margin-top:4px}
.container{max-width:1100px;margin:0 auto;padding:0 20px}
.features{padding:80px 0}
.features h2{text-align:center;font-size:2rem;margin-bottom:48px;color:#f8fafc}
.feature-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:32px}
.feature{background:#111827;border-radius:16px;padding:32px;border:1px solid #1e293b;transition:border-color 0.3s}
.feature:hover{border-color:#00d4ff}
.feature .icon{font-size:2rem;margin-bottom:16px}
.feature h3{font-size:1.1rem;margin-bottom:8px;color:#f8fafc}
.feature p{color:#94a3b8;font-size:0.95rem}
.pricing{padding:80px 0;background:#111827}
.pricing h2{text-align:center;font-size:2rem;margin-bottom:48px;color:#f8fafc}
.price-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:24px;max-width:900px;margin:0 auto}
.price-card{background:#0a0e1a;border-radius:16px;padding:32px;border:1px solid #1e293b;text-align:center}
.price-card.popular{border-color:#00d4ff;position:relative}
.price-card.popular::before{content:"MOST POPULAR";position:absolute;top:-12px;left:50%;transform:translateX(-50%);background:#00d4ff;color:#000;font-size:0.7rem;font-weight:700;padding:4px 12px;border-radius:12px}
.price-card h3{font-size:1.3rem;margin-bottom:8px;color:#f8fafc}
.price-card .price{font-size:2.5rem;font-weight:700;color:#00d4ff;margin:16px 0}
.price-card .price span{font-size:1rem;color:#64748b;font-weight:400}
.price-card ul{list-style:none;margin:24px 0}
.price-card ul li{padding:8px 0;color:#94a3b8;font-size:0.9rem;border-bottom:1px solid #1e293b}
.price-card ul li:last-child{border:none}
.price-card .btn{display:inline-block;padding:12px 32px;background:linear-gradient(135deg,#00d4ff,#7c3aed);color:#fff;border:none;border-radius:8px;font-size:1rem;cursor:pointer;text-decoration:none;margin-top:16px}
.footer{text-align:center;padding:40px 20px;color:#475569;font-size:0.85rem;border-top:1px solid #1e293b}
.footer a{color:#00d4ff;text-decoration:none}
</style>
</head>
<body>
<div class="hero">
<h1>FastCDN</h1>
<p class="tagline">Enterprise content delivery network powering the fastest websites and streaming platforms worldwide.</p>
<div class="stats">
<div class="stat"><div class="num">180+</div><div class="label">Edge Locations</div></div>
<div class="stat"><div class="num">99.99%</div><div class="label">Uptime SLA</div></div>
<div class="stat"><div class="num">12ms</div><div class="label">Avg Latency</div></div>
<div class="stat"><div class="num">50TB</div><div class="label">Daily Traffic</div></div>
</div>
</div>
<div class="container features">
<h2>Why FastCDN</h2>
<div class="feature-grid">
<div class="feature"><div class="icon">&#128640;</div><h3>Edge Caching</h3><p>Content cached at 180+ edge locations globally. Serve assets from the nearest node for sub-20ms load times.</p></div>
<div class="feature"><div class="icon">&#127916;</div><h3>Video Delivery</h3><p>Adaptive bitrate streaming with HLS/DASH support. Optimized for live and on-demand video at any scale.</p></div>
<div class="feature"><div class="icon">&#128274;</div><h3>DDoS Protection</h3><p>Always-on L3/L4/L7 mitigation. Absorb multi-Tbps attacks without impacting legitimate traffic.</p></div>
<div class="feature"><div class="icon">&#128187;</div><h3>Edge Computing</h3><p>Run serverless functions at the edge. Process requests, transform content, and personalize at lightning speed.</p></div>
<div class="feature"><div class="icon">&#128202;</div><h3>Real-Time Analytics</h3><p>Monitor traffic, performance, and security events with our real-time dashboard and alerting system.</p></div>
<div class="feature"><div class="icon">&#127760;</div><h3>Global Network</h3><p>Private backbone connecting all edge PoPs. Optimized routing ensures the fastest path for every request.</p></div>
</div>
</div>
<div class="pricing">
<h2>Simple Pricing</h2>
<div class="price-grid">
<div class="price-card">
<h3>Starter</h3>
<div class="price">$29<span>/mo</span></div>
<ul><li>100GB bandwidth</li><li>SSL included</li><li>Basic analytics</li><li>Email support</li></ul>
<a href="#" class="btn">Get Started</a>
</div>
<div class="price-card popular">
<h3>Professional</h3>
<div class="price">$99<span>/mo</span></div>
<ul><li>1TB bandwidth</li><li>Custom SSL certs</li><li>Advanced analytics</li><li>Edge functions</li><li>Priority support</li></ul>
<a href="#" class="btn">Get Started</a>
</div>
<div class="price-card">
<h3>Enterprise</h3>
<div class="price">Custom</div>
<ul><li>Unlimited bandwidth</li><li>Dedicated IPs</li><li>Custom SLA</li><li>24/7 phone support</li><li>Dedicated account manager</li></ul>
<a href="#" class="btn">Contact Sales</a>
</div>
</div>
</div>
<footer class="footer">
<p>&copy; 2024 FastCDN Inc. | <a href="/privacy">Privacy Policy</a> | <a href="/terms">Terms of Service</a> | <a href="/status">System Status</a></p>
</footer>
</body>
</html>`)
}

func robotsTxt() []byte {
	return []byte("User-agent: *\nDisallow: /api/\nDisallow: /ws/\n")
}

func getRealClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("CF-Connecting-IP"); xri != "" {
		return xri
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func handleRelay(w http.ResponseWriter, r *http.Request) {
	ip := getRealClientIP(r)

	if !rateLimiter.Allow(ip) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	if cfg.Auth.Enabled && cfg.Auth.Secret != "" {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+cfg.Auth.Secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WS upgrade failed: %v", err)
		return
	}
	defer ws.Close()

	log.Printf("WS connected: %s", ip)
	stats.AddConn()
	defer stats.RemoveConn()

	ws.SetReadLimit(int64(cfg.Relay.BufferSize * 2))
	ws.SetReadDeadline(time.Now().Add(30 * time.Second))

	_, firstMsg, err := ws.ReadMessage()
	if err != nil {
		log.Printf("WS read first msg failed from %s: %v", ip, err)
		return
	}

	frame, err := lib.ParseFrame(firstMsg)
	if err != nil {
		log.Printf("Invalid first frame from %s: %v", ip, err)
		return
	}
	if frame.Type != lib.FrameTypeNewStream {
		log.Printf("Expected NEW_STREAM, got %d from %s", frame.Type, ip)
		return
	}

	target, err := lib.ParseStreamPayload(frame.Payload)
	if err != nil {
		log.Printf("Invalid stream payload from %s: %v", ip, err)
		return
	}

	log.Printf("Stream %d: connecting to %s:%d from %s", frame.StreamID, target.Host, target.Port, ip)

	tcpAddr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	tcpConn, err := net.DialTimeout("tcp", tcpAddr, 10*time.Second)
	if err != nil {
		log.Printf("TCP connect to %s failed: %v", tcpAddr, err)
		statusFrame := lib.BuildFrame(lib.FrameTypeNewStream, frame.StreamID, []byte{lib.MuxStatusErr})
		ws.WriteMessage(websocket.BinaryMessage, statusFrame)
		return
	}
	defer tcpConn.Close()

	statusFrame := lib.BuildFrame(lib.FrameTypeNewStream, frame.StreamID, []byte{lib.MuxStatusOK})
	if err := ws.WriteMessage(websocket.BinaryMessage, statusFrame); err != nil {
		log.Printf("Send status failed: %v", err)
		return
	}

	scheduler := lib.NewFakeFrameScheduler(ws, cfg.Obfuscation)
	scheduler.Start()
	defer scheduler.Stop()

	ws.SetReadDeadline(time.Time{})
	ws.SetWriteDeadline(time.Time{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	idleTimeout := time.Duration(cfg.Relay.IdleTimeoutSec) * time.Second
	rotationTime := time.Duration(cfg.Relay.SessionRotationMin) * time.Minute
	startTime := time.Now()

	go func() {
		tcpToWs(ctx, tcpConn, ws, frame.StreamID, idleTimeout, cancel)
		cancel()
	}()

	wsToTcp(ctx, ws, tcpConn, frame.StreamID, idleTimeout, startTime, rotationTime, cancel)

	_ = ws.WriteMessage(websocket.BinaryMessage, lib.BuildFrame(lib.FrameTypeFin, frame.StreamID, nil))
	log.Printf("Stream %d closed (bytes in=%d out=%d fake=%d)",
		frame.StreamID, stats.totalBytesIn, stats.totalBytesOut, scheduler.BytesSent())
}

func wsToTcp(ctx context.Context, ws *websocket.Conn, tcp net.Conn, streamID uint32,
	idleTimeout time.Duration, startTime time.Time, rotationTime time.Duration, cancel context.CancelFunc) {

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		deadline := time.Now().Add(idleTimeout)
		ws.SetReadDeadline(deadline)

		mt, msg, err := ws.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("Stream %d: WS closed normally", streamID)
			} else {
				log.Printf("Stream %d: WS read error: %v", streamID, err)
			}
			return
		}

		if mt == websocket.TextMessage {
			continue
		}

		clean, err := lib.StripPadding(msg)
		if err != nil || len(clean) < lib.FrameHdrSize {
			continue
		}

		frame, err := lib.ParseFrame(clean)
		if err != nil {
			continue
		}

		switch frame.Type {
		case lib.FrameTypeData:
			delay := lib.BimodalDelay(cfg.Obfuscation.MinDelayMs, cfg.Obfuscation.MaxDelayMs)
			time.Sleep(delay)

			n, err := tcp.Write(frame.Payload)
			if err != nil {
				log.Printf("Stream %d: TCP write error: %v", streamID, err)
				return
			}
			stats.AddBytesOut(int64(n))

		case lib.FrameTypeClose, lib.FrameTypeFin:
			log.Printf("Stream %d: received %d from client", streamID, frame.Type)
			return
		}

		if time.Since(startTime) > rotationTime {
			log.Printf("Stream %d: session rotation triggered", streamID)
			return
		}
	}
}

func tcpToWs(ctx context.Context, tcp net.Conn, ws *websocket.Conn, streamID uint32,
	idleTimeout time.Duration, cancel context.CancelFunc) {

	buf := make([]byte, cfg.Relay.BufferSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		tcp.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := tcp.Read(buf)
		if err != nil {
			if err != io.EOF && !isTimeout(err) {
				log.Printf("Stream %d: TCP read error: %v", streamID, err)
			}
			return
		}

		if n == 0 {
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		payload := lib.BuildFrame(lib.FrameTypeData, streamID, data)
		obfuscated := lib.AddPadding(payload, cfg.Obfuscation.MinPadding, cfg.Obfuscation.MaxPadding)

		ws.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if err := ws.WriteMessage(websocket.BinaryMessage, obfuscated); err != nil {
			log.Printf("Stream %d: WS write error: %v", streamID, err)
			return
		}
		stats.AddBytesIn(int64(n))
	}
}

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

func main() {
	configPath := "config.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	loaded, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	cfg = *loaded

	if err := lib.ValidateFronting(&cfg.DomainFronting); err != nil {
		log.Fatalf("Invalid fronting config: %v", err)
	}

	rateLimiter = NewRateLimiter(cfg.RateLimit)
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		for range ticker.C {
			rateLimiter.Cleanup()
		}
	}()

	certPEM, keyPEM, err := loadCerts(cfg.Server.CertPath, cfg.Server.KeyPath)
	if err != nil {
		log.Printf("Could not load TLS certs: %v", err)
		log.Printf("Generating self-signed certs for development...")
		certPEM, keyPEM, err = generateSelfSigned(cfg.Server.Domain)
		if err != nil {
			log.Fatalf("Failed to generate self-signed certs: %v", err)
		}
		log.Printf("Self-signed certs generated for %s", cfg.Server.Domain)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write(robotsTxt())
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats.mu.Lock()
		info := map[string]interface{}{
			"status":   "ok",
			"active":   stats.activeConns,
			"total":    stats.totalConns,
			"uptime_s": int(time.Since(stats.startTime).Seconds()),
		}
		stats.mu.Unlock()
		json.NewEncoder(w).Encode(info)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			handleRelay(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(coverHTML())
	})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("Failed to create TLS cert pair: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	log.Printf("FastCDN relay starting on %s", server.Addr)
	log.Printf("Domain fronting: %v (front=%s)", cfg.DomainFronting.Enabled, cfg.DomainFronting.FrontHost)
	log.Printf("Obfuscation: pad=%d-%dms delay=%d-%dms fake_interval=%dms",
		cfg.Obfuscation.MinPadding, cfg.Obfuscation.MaxPadding,
		cfg.Obfuscation.MinDelayMs, cfg.Obfuscation.MaxDelayMs,
		cfg.Obfuscation.FakeFrameIntervalMs)
	log.Printf("Relay: idle=%ds max_conns=%d rotation=%dm",
		cfg.Relay.IdleTimeoutSec, cfg.Relay.MaxConnections, cfg.Relay.SessionRotationMin)

	// Start ShadowTLS listener if enabled
	if cfg.ShadowTLS.Enabled {
		stls, err := lib.NewShadowTLSServer(cfg.ShadowTLS, certPEM, keyPEM)
		if err != nil {
			log.Printf("ShadowTLS init failed: %v", err)
		} else {
			go func() {
				if err := stls.Start(cfg.Server.Host); err != nil {
					log.Printf("ShadowTLS start failed: %v", err)
				}
			}()
		}
	}

	certFile := filepath.Join("certs", "dev-cert.pem")
	keyFile := filepath.Join("certs", "dev-key.pem")
	os.MkdirAll("certs", 0755)
	os.WriteFile(certFile, certPEM, 0644)
	os.WriteFile(keyFile, keyPEM, 0600)

	log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
}
