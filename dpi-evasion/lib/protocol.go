package lib

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	FrameHdrSize     = 9
	FrameTypeNewStream = 0x01
	FrameTypeData      = 0x02
	FrameTypeClose     = 0x03
	FrameTypeFin       = 0x04

	MuxStatusOK  = 0x00
	MuxStatusErr = 0x01
)

var (
	ErrFrameTooShort  = errors.New("frame too short")
	ErrInvalidType    = errors.New("invalid frame type")
	ErrPayloadMismatch = errors.New("payload length mismatch")
)

type Frame struct {
	Type     uint8
	StreamID uint32
	Payload  []byte
}

func ParseFrame(data []byte) (*Frame, error) {
	if len(data) < FrameHdrSize {
		return nil, ErrFrameTooShort
	}
	ftype := data[0]
	if ftype < FrameTypeNewStream || ftype > FrameTypeFin {
		return nil, ErrInvalidType
	}
	sid := binary.BigEndian.Uint32(data[1:5])
	length := binary.BigEndian.Uint32(data[5:9])
	if uint32(len(data)-FrameHdrSize) < length {
		return nil, ErrPayloadMismatch
	}
	payload := make([]byte, length)
	copy(payload, data[FrameHdrSize:FrameHdrSize+int(length)])
	return &Frame{Type: ftype, StreamID: sid, Payload: payload}, nil
}

func BuildFrame(ftype uint8, streamID uint32, payload []byte) []byte {
	buf := make([]byte, FrameHdrSize+len(payload))
	buf[0] = ftype
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(payload)))
	copy(buf[FrameHdrSize:], payload)
	return buf
}

type StreamTarget struct {
	Host string
	Port uint16
}

func ParseStreamPayload(payload []byte) (*StreamTarget, error) {
	if len(payload) < 3 {
		return nil, fmt.Errorf("payload too short for stream target")
	}
	hostLen := int(payload[0])
	if len(payload) < 1+hostLen+2 {
		return nil, fmt.Errorf("payload too short for host+port")
	}
	host := string(payload[1 : 1+hostLen])
	port := binary.BigEndian.Uint16(payload[1+hostLen : 3+hostLen])
	return &StreamTarget{Host: host, Port: port}, nil
}

func BuildStreamPayload(host string, port uint16) []byte {
	hostBytes := []byte(host)
	buf := make([]byte, 1+len(hostBytes)+2)
	buf[0] = byte(len(hostBytes))
	copy(buf[1:], hostBytes)
	binary.BigEndian.PutUint16(buf[1+len(hostBytes):], port)
	return buf
}
