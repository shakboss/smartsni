package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

type ClientConfig struct {
	Server    string `json:"server"`
	Port      int    `json:"port"`
	Password  string `json:"password"`
	SNI       string `json:"sni"`
	Mode      string `json:"mode"`
	WSPath    string `json:"wsPath"`
	Secret    string `json:"secret"`
	SOCKSPort int    `json:"socksPort"`
}

var (
	configPath string
	config     ClientConfig
	transport  Transport
	stats      = &ClientStats{}
)

type ClientStats struct {
	mu           sync.Mutex
	activeConns  int
	totalConns   int
	totalBytesIn int64
	totalBytesOut int64
}

func (s *ClientStats) AddConn() {
	s.mu.Lock()
	s.activeConns++
	s.totalConns++
	s.mu.Unlock()
}

func (s *ClientStats) RemoveConn() {
	s.mu.Lock()
	s.activeConns--
	s.mu.Unlock()
}

func main() {
	flag.StringVar(&configPath, "config", "client-config.json", "path to config file")
	flag.Parse()

	if err := loadConfig(configPath); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create transport
	serverAddr := fmt.Sprintf("%s:%d", config.Server, config.Port)
	switch config.Mode {
	case "shadowtls":
		transport = NewShadowTLSTransport(serverAddr, config.Password, config.SNI)
		log.Printf("Mode: ShadowTLS (server=%s, sni=%s)", serverAddr, config.SNI)
	case "websocket":
		transport = NewWebSocketTransport(serverAddr, config.WSPath, config.Secret)
		log.Printf("Mode: WebSocket (server=%s, path=%s)", serverAddr, config.WSPath)
	default:
		log.Fatalf("Unknown mode: %s (use 'shadowtls' or 'websocket')", config.Mode)
	}

	// Start SOCKS5 listener
	addr := fmt.Sprintf("127.0.0.1:%d", config.SOCKSPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}
	log.Printf("SOCKS5 proxy listening on %s", addr)
	log.Printf("Configure your browser: SOCKS5 proxy = 127.0.0.1:%d", config.SOCKSPort)

	// Stats reporting
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		for range ticker.C {
			stats.mu.Lock()
			log.Printf("Stats: active=%d total=%d bytes_in=%d bytes_out=%d",
				stats.activeConns, stats.totalConns, stats.totalBytesIn, stats.totalBytesOut)
			stats.mu.Unlock()
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}
	if config.Port == 0 {
		config.Port = 443
	}
	if config.SOCKSPort == 0 {
		config.SOCKSPort = 1080
	}
	if config.WSPath == "" {
		config.WSPath = "/wstunnel"
	}
	if config.SNI == "" {
		config.SNI = "www.microsoft.com"
	}
	if config.Mode == "" {
		config.Mode = "shadowtls"
	}
	return nil
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	stats.AddConn()
	defer stats.RemoveConn()

	// Read SOCKS5 request
	req, err := ReadSOCKS5Client(conn)
	if err != nil {
		log.Printf("SOCKS5 error: %v", err)
		return
	}

	log.Printf("SOCKS5 CONNECT: %s:%d", req.Host, req.Port)

	// Connect to relay
	relay, err := transport.Connect(req.Host, req.Port)
	if err != nil {
		log.Printf("Relay connect failed: %v", err)
		SendSOCKS5Error(conn, 0x05)
		return
	}
	defer relay.Close()

	// Send SOCKS5 success
	if err := SendSOCKS5Success(conn); err != nil {
		log.Printf("SOCKS5 success send failed: %v", err)
		return
	}

	// Bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				_, werr := relay.Write(buf[:n])
				if werr != nil {
					return
				}
				stats.mu.Lock()
				stats.totalBytesOut += int64(n)
				stats.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := relay.Read(buf)
			if n > 0 {
				_, werr := conn.Write(buf[:n])
				if werr != nil {
					return
				}
				stats.mu.Lock()
				stats.totalBytesIn += int64(n)
				stats.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	wg.Wait()
}
