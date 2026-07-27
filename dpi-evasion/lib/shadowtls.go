package lib

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

const (
	TLSRecordHeaderSize    = 5
	TLSContentTypeApp      = 23
	TLSContentTypeAlert    = 21
	TLSHandshakeClientHello = 1
	TLSHandshakeServerHello = 2
	TLSHandshakeFinished   = 20
)

type ShadowTLSConfig struct {
	Enabled         bool   `json:"enabled"`
	ListenPort      int    `json:"listenPort"`
	Password        string `json:"password"`
	HandshakeServer string `json:"handshakeServer"`
	HandshakePort   int    `json:"handshakePort"`
	StrictMode      bool   `json:"strictMode"`
}

type TLSRecord struct {
	ContentType uint8
	MajorVer    uint8
	MinorVer    uint8
	Length      uint16
	Body        []byte
}

func ReadTLSRecord(r io.Reader) (*TLSRecord, error) {
	hdr := make([]byte, TLSRecordHeaderSize)
	_, err := io.ReadFull(r, hdr)
	if err != nil {
		return nil, fmt.Errorf("read TLS header: %w", err)
	}
	length := binary.BigEndian.Uint16(hdr[3:5])
	if length > 16384+2048 {
		return nil, fmt.Errorf("TLS record too large: %d", length)
	}
	body := make([]byte, length)
	_, err = io.ReadFull(r, body)
	if err != nil {
		return nil, fmt.Errorf("read TLS body: %w", err)
	}
	return &TLSRecord{
		ContentType: hdr[0],
		MajorVer:    hdr[1],
		MinorVer:    hdr[2],
		Length:      length,
		Body:        body,
	}, nil
}

func WriteTLSRecord(w io.Writer, rec *TLSRecord) error {
	hdr := make([]byte, TLSRecordHeaderSize)
	hdr[0] = rec.ContentType
	hdr[1] = rec.MajorVer
	hdr[2] = rec.MinorVer
	binary.BigEndian.PutUint16(hdr[3:5], rec.Length)
	_, err := w.Write(append(hdr, rec.Body...))
	return err
}

func ExtractSNI(clientHello []byte) (string, error) {
	if len(clientHello) < 5 || clientHello[0] != TLSHandshakeClientHello {
		return "", fmt.Errorf("not a ClientHello")
	}
	if len(clientHello) < 43 {
		return "", fmt.Errorf("ClientHello too short")
	}
	offset := 43
	sessionIDLen := int(clientHello[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(clientHello) {
		return "", fmt.Errorf("truncated cipher suites")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(clientHello[offset : offset+2]))
	offset += 2 + cipherSuitesLen
	if offset+1 > len(clientHello) {
		return "", fmt.Errorf("truncated compression")
	}
	compressionLen := int(clientHello[offset])
	offset += 1 + compressionLen
	if offset+2 > len(clientHello) {
		return "", fmt.Errorf("truncated extensions")
	}
	extensionsLen := int(binary.BigEndian.Uint16(clientHello[offset : offset+2]))
	offset += 2
	endOfExts := offset + extensionsLen
	for offset+4 <= endOfExts {
		extType := binary.BigEndian.Uint16(clientHello[offset : offset+2])
		extLen := binary.BigEndian.Uint16(clientHello[offset+2 : offset+4])
		if extType == 0 {
			sniOffset := offset + 4
			if sniOffset+5 > endOfExts {
				return "", fmt.Errorf("truncated SNI extension")
			}
			if clientHello[sniOffset+2] != 0 {
				return "", fmt.Errorf("unexpected SNI name type")
			}
			nameLen := int(binary.BigEndian.Uint16(clientHello[sniOffset+3 : sniOffset+5]))
			nameOffset := sniOffset + 5
			if nameOffset+nameLen > endOfExts {
				return "", fmt.Errorf("SNI name extends beyond extensions")
			}
			return string(clientHello[nameOffset : nameOffset+nameLen]), nil
		}
		offset += 4 + int(extLen)
	}
	return "", nil
}

func ExtractServerRandom(serverHello []byte) ([]byte, error) {
	if len(serverHello) < 2 || serverHello[0] != TLSHandshakeServerHello {
		return nil, fmt.Errorf("not a ServerHello")
	}
	if len(serverHello) < 39 {
		return nil, fmt.Errorf("ServerHello too short")
	}
	return serverHello[6:38], nil
}

func DeriveXORKey(password string, serverRandom []byte) []byte {
	h := sha256.New()
	h.Write([]byte(password))
	h.Write(serverRandom)
	return h.Sum(nil)
}

func XORCrypt(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

func ComputeAuthHash(password string, clientRandom, serverRandom []byte) []byte {
	h := hmac.New(sha256.New, []byte(password))
	h.Write(clientRandom)
	h.Write(serverRandom)
	return h.Sum(nil)[:32]
}

func VerifyAuth(authData []byte, password string, clientRandom, serverRandom []byte) bool {
	expected := ComputeAuthHash(password, clientRandom, serverRandom)
	if len(authData) < 32 {
		return false
	}
	return hmac.Equal(authData[:32], expected)
}

func ParseTargetFromAuth(authData []byte) (string, uint16, error) {
	if len(authData) < 35 {
		return "", 0, fmt.Errorf("auth data too short for target")
	}
	offset := 32
	hostLen := int(authData[offset])
	offset++
	if offset+hostLen+2 > len(authData) {
		return "", 0, fmt.Errorf("truncated target host")
	}
	host := string(authData[offset : offset+hostLen])
	offset += hostLen
	port := binary.BigEndian.Uint16(authData[offset : offset+2])
	return host, port, nil
}

func SendTLSAlert(conn net.Conn) {
	alert := []byte{2, 40}
	rec := &TLSRecord{
		ContentType: TLSContentTypeAlert,
		MajorVer:    0x03,
		MinorVer:    0x03,
		Length:      2,
		Body:        alert,
	}
	WriteTLSRecord(conn, rec)
}

type handshakeResult struct {
	serverRandom []byte
	err          error
}

func proxyFullHandshake(clientRaw, hsConn net.Conn, clientHelloRec *TLSRecord) (*handshakeResult, error) {
	// Forward ClientHello to handshake server
	if err := WriteTLSRecord(hsConn, clientHelloRec); err != nil {
		return nil, fmt.Errorf("forward ClientHello: %w", err)
	}

	result := make(chan *handshakeResult, 1)

	// Read from handshake server, forward to client, extract ServerRandom
	go func() {
		var serverRandom []byte
		clientFinished := false
		serverFinished := false

		for {
			rec, err := ReadTLSRecord(hsConn)
			if err != nil {
				result <- &handshakeResult{serverRandom, err}
				return
			}

			if err := WriteTLSRecord(clientRaw, rec); err != nil {
				result <- &handshakeResult{serverRandom, err}
				return
			}

			// Track handshake state
			if rec.ContentType == 22 && len(rec.Body) > 0 {
				hsType := rec.Body[0]
				if hsType == TLSHandshakeServerHello && serverRandom == nil {
					sr, err := ExtractServerRandom(rec.Body)
					if err == nil {
						serverRandom = sr
					}
				}
				if hsType == TLSHandshakeFinished {
					serverFinished = true
				}
			}

			if clientFinished && serverFinished {
				result <- &handshakeResult{serverRandom, nil}
				return
			}
		}
	}()

	// Read from client, forward to handshake server, detect client Finished
	go func() {
		for {
			rec, err := ReadTLSRecord(clientRaw)
			if err != nil {
				return
			}
			if err := WriteTLSRecord(hsConn, rec); err != nil {
				return
			}
			if rec.ContentType == 22 && len(rec.Body) > 0 && rec.Body[0] == TLSHandshakeFinished {
				// Client Finished sent, now wait for server Finished
				// The goroutine above will detect it
			}
		}
	}()

	select {
	case res := <-result:
		return res, nil
	case <-time.After(15 * time.Second):
		return nil, fmt.Errorf("handshake timeout")
	}
}

type ShadowTLSServer struct {
	config      ShadowTLSConfig
	tlsConfig   *tls.Config
	activeConns int64
	mu          sync.Mutex
}

func NewShadowTLSServer(cfg ShadowTLSConfig, certPEM, keyPEM []byte) (*ShadowTLSServer, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load TLS cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	return &ShadowTLSServer{config: cfg, tlsConfig: tlsCfg}, nil
}

func (s *ShadowTLSServer) Start(host string) error {
	addr := fmt.Sprintf("%s:%d", host, s.config.ListenPort)
	listener, err := tls.Listen("tcp", addr, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("ShadowTLS listen: %w", err)
	}
	log.Printf("ShadowTLS: listening on %s (hs=%s:%d, strict=%v)",
		addr, s.config.HandshakeServer, s.config.HandshakePort, s.config.StrictMode)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("ShadowTLS: accept error: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *ShadowTLSServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	s.mu.Lock()
	s.activeConns++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.activeConns--
		s.mu.Unlock()
	}()

	// Step 1: Read raw TLS ClientHello
	clientHelloRec, err := ReadTLSRecord(conn)
	if err != nil {
		log.Printf("ShadowTLS: read ClientHello failed: %v", err)
		return
	}

	if clientHelloRec.ContentType != 22 || len(clientHelloRec.Body) == 0 || clientHelloRec.Body[0] != TLSHandshakeClientHello {
		log.Printf("ShadowTLS: not a ClientHello from %s", conn.RemoteAddr())
		return
	}

	sni, _ := ExtractSNI(clientHelloRec.Body)
	log.Printf("ShadowTLS: conn from %s, SNI=%s", conn.RemoteAddr(), sni)

	// Step 2: Connect to handshake server
	hsAddr := net.JoinHostPort(s.config.HandshakeServer, fmt.Sprintf("%d", s.config.HandshakePort))
	hsConn, err := net.DialTimeout("tcp", hsAddr, 10*time.Second)
	if err != nil {
		log.Printf("ShadowTLS: connect to hs %s failed: %v", hsAddr, err)
		return
	}
	defer hsConn.Close()

	// Step 3: Proxy full TLS handshake
	hres, err := proxyFullHandshake(conn, hsConn, clientHelloRec)
	if err != nil {
		log.Printf("ShadowTLS: handshake proxy failed: %v", err)
		return
	}
	if hres.serverRandom == nil {
		log.Printf("ShadowTLS: no ServerRandom extracted")
		return
	}

	// Step 4: Read first Application Data from client
	appData, err := readAppDataWithTimeout(conn, 30*time.Second)
	if err != nil {
		log.Printf("ShadowTLS: read AppData failed: %v", err)
		return
	}

	// Step 5: Verify auth (client sends HMAC + target)
	// For simplicity, we use the first 32 bytes of ClientHello as clientRandom
	// In production, the client would send its actual client_random
	clientRandom := make([]byte, 32)
	if len(clientHelloRec.Body) >= 32 {
		copy(clientRandom, clientHelloRec.Body[:32])
	} else {
		copy(clientRandom, clientHelloRec.Body)
	}

	authenticated := VerifyAuth(appData.Body, s.config.Password, clientRandom, hres.serverRandom)

	if !authenticated {
		if s.config.StrictMode {
			log.Printf("ShadowTLS: auth FAILED from %s (strict)", conn.RemoteAddr())
			SendTLSAlert(conn)
			return
		}
		log.Printf("ShadowTLS: auth FAILED from %s, cover traffic to %s", conn.RemoteAddr(), hsAddr)
		// Forward remaining traffic to handshake server
		done := make(chan struct{})
		go func() { io.Copy(hsConn, conn); close(done) }()
		go func() { io.Copy(conn, hsConn); <-done }()
		io.Copy(conn, hsConn)
		return
	}

	// Step 6: Parse target from auth payload
	targetHost, targetPort, err := ParseTargetFromAuth(appData.Body)
	if err != nil {
		log.Printf("ShadowTLS: parse target failed: %v", err)
		SendTLSAlert(conn)
		return
	}

	log.Printf("ShadowTLS: auth OK %s -> %s:%d", conn.RemoteAddr(), targetHost, targetPort)

	// Step 7: Connect to target
	targetAddr := net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort))
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("ShadowTLS: connect to target %s failed: %v", targetAddr, err)
		SendTLSAlert(conn)
		return
	}
	defer targetConn.Close()

	// Step 8: XOR-encrypted relay
	xorKey := DeriveXORKey(s.config.Password, hres.serverRandom)
	relayXOR(conn, targetConn, xorKey)
	log.Printf("ShadowTLS: relay done %s -> %s:%d", conn.RemoteAddr(), targetHost, targetPort)
}

func readAppDataWithTimeout(conn net.Conn, timeout time.Duration) (*TLSRecord, error) {
	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})

	for {
		rec, err := ReadTLSRecord(conn)
		if err != nil {
			return nil, err
		}
		if rec.ContentType == TLSContentTypeApp {
			return rec, nil
		}
		if rec.ContentType == TLSContentTypeAlert {
			return nil, fmt.Errorf("TLS Alert received")
		}
	}
}

func relayXOR(clientConn, targetConn net.Conn, key []byte) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyAndXOR := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				encrypted := XORCrypt(buf[:n], key)
				if _, werr := dst.Write(encrypted); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}

	go copyAndXOR(targetConn, clientConn)
	go copyAndXOR(clientConn, targetConn)
	wg.Wait()
}
