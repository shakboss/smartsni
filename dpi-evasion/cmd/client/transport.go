package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/gorilla/websocket"
	"github.com/smartsni/dpi-evasion/lib"
)

type Transport interface {
	Connect(targetHost string, targetPort uint16) (io.ReadWriteCloser, error)
	Close() error
}

type ShadowTLSTransport struct {
	serverAddr string
	password   string
	sni        string
	tlsConfig  *tls.Config
}

func NewShadowTLSTransport(serverAddr, password, sni string) *ShadowTLSTransport {
	return &ShadowTLSTransport{
		serverAddr: serverAddr,
		password:   password,
		sni:        sni,
		tlsConfig: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
	}
}

func (t *ShadowTLSTransport) Connect(targetHost string, targetPort uint16) (io.ReadWriteCloser, error) {
	conn, err := net.DialTimeout("tcp", t.serverAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("tcp connect: %w", err)
	}

	tlsConn := tls.Client(conn, t.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	state := tlsConn.ConnectionState()

	// Derive shared secret from TLS session verify data
	h := sha256.New()
	h.Write([]byte(t.password))
	if len(state.TLSUnique) > 0 {
		h.Write(state.TLSUnique)
	} else {
		h.Write([]byte(t.serverAddr))
	}
	h.Write([]byte(t.sni))
	serverRandom := h.Sum(nil)

	// Client random from password + target
	clientRandom := make([]byte, 32)
	ch := sha256.New()
	ch.Write([]byte(t.password))
	ch.Write([]byte(targetHost))
	copy(clientRandom, ch.Sum(nil))

	// Auth hash
	authHash := computeAuthHash(t.password, clientRandom, serverRandom)

	// Build auth payload: [hash:32][host_len:1][host][port:2]
	hostBytes := []byte(targetHost)
	authPayload := make([]byte, 32+1+len(hostBytes)+2)
	copy(authPayload, authHash)
	authPayload[32] = byte(len(hostBytes))
	copy(authPayload[33:], hostBytes)
	binary.BigEndian.PutUint16(authPayload[33+len(hostBytes):], targetPort)

	// Send auth
	_, err = tlsConn.Write(authPayload)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("send auth: %w", err)
	}

	// Read status response from server
	statusBuf := make([]byte, 1)
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err = io.ReadFull(tlsConn, statusBuf)
	tlsConn.SetReadDeadline(time.Time{})
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("read status: %w", err)
	}
	if statusBuf[0] != 0x00 {
		tlsConn.Close()
		return nil, fmt.Errorf("server rejected connection: %d", statusBuf[0])
	}

	// XOR-encrypted connection
	xorKey := lib.DeriveXORKey(t.password, serverRandom)
	return &XORConn{Conn: tlsConn, key: xorKey}, nil
}

func (t *ShadowTLSTransport) Close() error {
	return nil
}

type WebSocketTransport struct {
	serverAddr string
	wsPath     string
	secret     string
}

func NewWebSocketTransport(serverAddr, wsPath, secret string) *WebSocketTransport {
	return &WebSocketTransport{
		serverAddr: serverAddr,
		wsPath:     wsPath,
		secret:     secret,
	}
}

func (t *WebSocketTransport) Connect(targetHost string, targetPort uint16) (io.ReadWriteCloser, error) {
	url := fmt.Sprintf("wss://%s%s", t.serverAddr, t.wsPath)
	header := make(map[string][]string)
	if t.secret != "" {
		header["Authorization"] = []string{fmt.Sprintf("Bearer %s", t.secret)}
	}

	dialer := &websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	ws, _, err := dialer.Dial(url, header)
	if err != nil {
		return nil, fmt.Errorf("ws dial: %w", err)
	}

	payload := lib.BuildStreamPayload(targetHost, targetPort)
	frame := lib.BuildFrame(lib.FrameTypeNewStream, 1, payload)
	if err := ws.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		ws.Close()
		return nil, fmt.Errorf("send NEW_STREAM: %w", err)
	}

	_, msg, err := ws.ReadMessage()
	if err != nil {
		ws.Close()
		return nil, fmt.Errorf("read status: %w", err)
	}

	if len(msg) < lib.FrameHdrSize+1 {
		ws.Close()
		return nil, fmt.Errorf("invalid status frame")
	}
	if msg[9] != 0x00 {
		ws.Close()
		return nil, fmt.Errorf("server rejected connection")
	}

	return &WSConn{ws: ws, streamID: 1}, nil
}

func (t *WebSocketTransport) Close() error {
	return nil
}

type XORConn struct {
	net.Conn
	key []byte
}

func (c *XORConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		decrypted := lib.XORCrypt(b[:n], c.key)
		copy(b, decrypted)
	}
	return n, err
}

func (c *XORConn) Write(b []byte) (int, error) {
	encrypted := lib.XORCrypt(b, c.key)
	return c.Conn.Write(encrypted)
}

type WSConn struct {
	ws       *websocket.Conn
	streamID uint32
}

func (c *WSConn) Read(b []byte) (int, error) {
	for {
		mt, msg, err := c.ws.ReadMessage()
		if err != nil {
			return 0, err
		}
		if mt != websocket.BinaryMessage {
			continue
		}
		if len(msg) < lib.FrameHdrSize {
			continue
		}
		frame, err := lib.ParseFrame(msg)
		if err != nil {
			continue
		}
		if frame.Type == lib.FrameTypeData && frame.StreamID == c.streamID {
			n := copy(b, frame.Payload)
			return n, nil
		}
	}
}

func (c *WSConn) Write(b []byte) (int, error) {
	frame := lib.BuildFrame(lib.FrameTypeData, c.streamID, b)
	return len(b), c.ws.WriteMessage(websocket.BinaryMessage, frame)
}

func (c *WSConn) Close() error {
	closeFrame := lib.BuildFrame(lib.FrameTypeClose, c.streamID, nil)
	c.ws.WriteMessage(websocket.BinaryMessage, closeFrame)
	return c.ws.Close()
}

func computeAuthHash(password string, clientRandom, serverRandom []byte) []byte {
	h := hmac.New(sha256.New, []byte(password))
	h.Write(clientRandom)
	h.Write(serverRandom)
	return h.Sum(nil)[:32]
}
