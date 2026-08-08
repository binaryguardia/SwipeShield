// Package websocket implements a minimal, correct RFC 6455 frame codec plus
// per-message inspection and rate limiting for persistent connections. The
// proxy uses it to inspect messages on live WebSocket tunnels — a handshake
// alone is not enough once an "allowed" connection becomes an uninspected
// channel.
package websocket

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Opcodes.
const (
	OpContinuation = 0x0
	OpText         = 0x1
	OpBinary       = 0x2
	OpClose        = 0x8
	OpPing         = 0x9
	OpPong         = 0xA
)

// MaxFrameBytes bounds a single frame's payload.
const MaxFrameBytes = 16 << 20

// Frame is one parsed WebSocket frame. Payload is always unmasked.
type Frame struct {
	FIN     bool
	RSV1    bool
	RSV2    bool
	RSV3    bool
	Opcode  byte
	Masked  bool
	Payload []byte
}

// ReadFrame reads one frame from r, unmasking the payload if masked.
func ReadFrame(r io.Reader) (Frame, error) {
	var f Frame
	var b0, b1 [1]byte
	if _, err := io.ReadFull(r, b0[:]); err != nil {
		return f, err
	}
	f.FIN = b0[0]&0x80 != 0
	f.RSV1 = b0[0]&0x40 != 0
	f.RSV2 = b0[0]&0x20 != 0
	f.RSV3 = b0[0]&0x10 != 0
	f.Opcode = b0[0] & 0x0f
	if _, err := io.ReadFull(r, b1[:]); err != nil {
		return f, err
	}
	f.Masked = b1[0]&0x80 != 0
	length := uint64(b1[0] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return f, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return f, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > MaxFrameBytes {
		return f, fmt.Errorf("websocket: frame too large (%d bytes)", length)
	}
	var maskKey [4]byte
	if f.Masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return f, err
		}
	}
	f.Payload = make([]byte, length)
	if _, err := io.ReadFull(r, f.Payload); err != nil {
		return f, err
	}
	if f.Masked {
		for i := range f.Payload {
			f.Payload[i] ^= maskKey[i%4]
		}
	}
	return f, nil
}

// WriteFrame writes one frame. When f.Masked is set the payload is masked
// with a fresh key (client role); otherwise it is sent unmasked (server role).
func WriteFrame(w io.Writer, f Frame) error {
	return writeFrame(w, f, f.Masked)
}

// WriteFrameServer writes a frame without masking, as a WebSocket server must
// (servers must not mask frames they send to clients). Used by the proxy when
// relaying backend->client traffic.
func WriteFrameServer(w io.Writer, f Frame) error {
	return writeFrame(w, f, false)
}

func writeFrame(w io.Writer, f Frame, mask bool) error {
	if len(f.Payload) > MaxFrameBytes {
		return fmt.Errorf("websocket: frame too large (%d bytes)", len(f.Payload))
	}
	var hdr [14]byte
	hdr[0] = f.Opcode
	if f.FIN {
		hdr[0] |= 0x80
	}
	if f.RSV1 {
		hdr[0] |= 0x40
	}
	if f.RSV2 {
		hdr[0] |= 0x20
	}
	if f.RSV3 {
		hdr[0] |= 0x10
	}
	l := len(f.Payload)
	if mask {
		hdr[1] = 0x80
	}
	if l <= 125 {
		hdr[1] |= byte(l)
		_, err := w.Write(hdr[:2])
		if err != nil {
			return err
		}
	} else if l <= 0xffff {
		hdr[1] |= 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(l))
		if _, err := w.Write(hdr[:4]); err != nil {
			return err
		}
	} else {
		hdr[1] |= 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(l))
		if _, err := w.Write(hdr[:10]); err != nil {
			return err
		}
	}
	if mask {
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		if _, err := w.Write(key[:]); err != nil {
			return err
		}
		buf := make([]byte, len(f.Payload))
		copy(buf, f.Payload)
		for i := range buf {
			buf[i] ^= key[i%4]
		}
		_, err := w.Write(buf)
		return err
	}
	_, err := w.Write(f.Payload)
	return err
}

// WriteText sends a masked text message (client role).
func WriteText(w io.Writer, data []byte) error {
	return WriteFrame(w, Frame{FIN: true, Opcode: OpText, Masked: true, Payload: data})
}

// IsControl reports whether an opcode is a control frame.
func IsControl(op byte) bool { return op >= 0x8 }

var errClosed = errors.New("websocket: close")
