package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	Socks5Version = 0x05
	Socks5NoAuth  = 0x00
	Socks5Connect = 0x01
	Socks5IPv4    = 0x01
	Socks5Domain  = 0x03
	Socks5IPv6    = 0x04
)

type SOCKS5Request struct {
	Command byte
	Host    string
	Port    uint16
}

func ReadSOCKS5Client(conn net.Conn) (*SOCKS5Request, error) {
	// Read greeting: [version, nmethods, methods...]
	hdr := make([]byte, 2)
	_, err := io.ReadFull(conn, hdr)
	if err != nil {
		return nil, fmt.Errorf("read greeting: %w", err)
	}
	if hdr[0] != Socks5Version {
		return nil, fmt.Errorf("unsupported SOCKS version: %d", hdr[0])
	}
	methods := make([]byte, hdr[1])
	_, err = io.ReadFull(conn, methods)
	if err != nil {
		return nil, fmt.Errorf("read methods: %w", err)
	}

	// Reply: no auth required
	_, err = conn.Write([]byte{Socks5Version, Socks5NoAuth})
	if err != nil {
		return nil, fmt.Errorf("write method selection: %w", err)
	}

	// Read request: [version, cmd, rsv, atyp, addr..., port]
	req := make([]byte, 4)
	_, err = io.ReadFull(conn, req)
	if err != nil {
		return nil, fmt.Errorf("read request header: %w", err)
	}
	if req[0] != Socks5Version || req[1] != Socks5Connect {
		conn.Write([]byte{Socks5Version, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return nil, fmt.Errorf("unsupported command: %d", req[1])
	}

	var host string
	switch req[3] {
	case Socks5IPv4:
		addr := make([]byte, 4)
		_, err = io.ReadFull(conn, addr)
		if err != nil {
			return nil, fmt.Errorf("read IPv4: %w", err)
		}
		host = net.IP(addr).String()
	case Socks5Domain:
		lenBuf := make([]byte, 1)
		_, err = io.ReadFull(conn, lenBuf)
		if err != nil {
			return nil, fmt.Errorf("read domain len: %w", err)
		}
		domain := make([]byte, lenBuf[0])
		_, err = io.ReadFull(conn, domain)
		if err != nil {
			return nil, fmt.Errorf("read domain: %w", err)
		}
		host = string(domain)
	case Socks5IPv6:
		addr := make([]byte, 16)
		_, err = io.ReadFull(conn, addr)
		if err != nil {
			return nil, fmt.Errorf("read IPv6: %w", err)
		}
		host = net.IP(addr).String()
	default:
		return nil, fmt.Errorf("unknown address type: %d", req[3])
	}

	portBuf := make([]byte, 2)
	_, err = io.ReadFull(conn, portBuf)
	if err != nil {
		return nil, fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return &SOCKS5Request{Command: req[1], Host: host, Port: port}, nil
}

func SendSOCKS5Success(conn net.Conn) error {
	_, err := conn.Write([]byte{Socks5Version, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func SendSOCKS5Error(conn net.Conn, errCode byte) {
	conn.Write([]byte{Socks5Version, errCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}
