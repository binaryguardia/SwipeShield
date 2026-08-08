package websocket

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/binaryguardia/swipeshield/internal/decision"
)

// RelayOption is a knobs struct for Relay.
type RelayOption struct {
	// OnViolation, when set, is called for every dropped message with the
	// reasons that caused the drop. The proxy uses it to emit SIEM events.
	OnViolation func(reasons []decision.Reason)
}

// Relay bridges two WebSocket peers, inspecting every client->server frame.
// It enforces the client role (masking outbound, unmasking inbound) on the
// client side and the server role (no masking) toward the client. Control
// frames pass through untouched; a violating data frame is dropped and the
// connection is closed with a 1008 policy-violation close code.
func Relay(ctx context.Context, client, backend net.Conn, insp *Inspector, clientIP, apiKey string, opt RelayOption) error {
	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		errCh <- relayClientToBackend(ctx, client, backend, insp, clientIP, apiKey, opt)
	}()
	go func() {
		defer wg.Done()
		errCh <- relayBackendToClient(ctx, backend, client)
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// relayClientToBackend reads masked client frames, inspects payloads, and
// forwards them (masked, client role) to the backend.
func relayClientToBackend(ctx context.Context, client, backend net.Conn, insp *Inspector, clientIP, apiKey string, opt RelayOption) error {
	for {
		f, err := ReadFrame(client)
		if err != nil {
			return err
		}
		if IsControl(f.Opcode) {
			if err := WriteFrame(backend, f); err != nil {
				return err
			}
			continue
		}
		if insp != nil {
			reasons, ok := insp.InspectMessage(ctx, clientIP, apiKey, f.Payload, f.Opcode)
			if !ok {
				if opt.OnViolation != nil {
					opt.OnViolation(reasons)
				}
				closeFrame := Frame{FIN: true, Opcode: OpClose, Payload: []byte{0x03, 0xf0}} // 1008 policy violation
				_ = WriteFrameServer(client, closeFrame)                                    // tell the client why
				_ = WriteFrame(backend, Frame{Masked: true, FIN: true, Opcode: OpClose, Payload: []byte{0x03, 0xf0}}) // masked: toward the backend the relay is a client
				return fmt.Errorf("websocket: message rejected by inspection")
			}
		}
		if err := WriteFrame(backend, f); err != nil {
			return err
		}
	}
}

// relayBackendToClient forwards unmasked server frames back to the client,
// re-masking only if needed (it is not — servers send unmasked frames).
func relayBackendToClient(ctx context.Context, backend, client net.Conn) error {
	_ = ctx
	for {
		f, err := ReadFrame(backend)
		if err != nil {
			return err
		}
		if err := WriteFrameServer(client, f); err != nil {
			return err
		}
	}
}

var _ = time.Now
