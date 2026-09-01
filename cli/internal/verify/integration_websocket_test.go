package verify

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
)

// wsEchoHandler handles WebSocket upgrade via http.Hijacker and echoes text frames back.
func wsEchoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.ToLower(r.Header.Get("Upgrade")) != "websocket" {
			w.WriteHeader(200)
			fmt.Fprint(w, "not a websocket request")
			return
		}

		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return
		}

		conn, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		// Compute Sec-WebSocket-Accept
		key := r.Header.Get("Sec-WebSocket-Key")
		h := sha1.New()
		h.Write([]byte(key + wsGUID))
		accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

		// Send 101 response
		bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
		bufrw.WriteString("Upgrade: websocket\r\n")
		bufrw.WriteString("Connection: Upgrade\r\n")
		fmt.Fprintf(bufrw, "Sec-WebSocket-Accept: %s\r\n", accept)
		bufrw.WriteString("\r\n")
		bufrw.Flush()

		// Read one frame and echo it back (unmasked for server->client)
		header := make([]byte, 2)
		if _, err := conn.Read(header); err != nil {
			return
		}
		payloadLen := int(header[1] & 0x7F)
		masked := header[1]&0x80 != 0

		var maskKey []byte
		if masked {
			maskKey = make([]byte, 4)
			if _, err := conn.Read(maskKey); err != nil {
				return
			}
		}

		payload := make([]byte, payloadLen)
		if payloadLen > 0 {
			n := 0
			for n < payloadLen {
				read, err := conn.Read(payload[n:])
				if err != nil {
					return
				}
				n += read
			}
		}

		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}

		// Send echo response (unmasked)
		var resp []byte
		resp = append(resp, 0x81) // FIN=1, text
		resp = append(resp, byte(payloadLen))
		resp = append(resp, payload...)
		conn.Write(resp)
	}
}

func TestWebSocket_Injection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, wsEchoHandler())

	// Convert http:// to ws://
	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws"

	result, err := VerifyWebSocket(WebSocketConfig{
		URL:         wsURL,
		Technique:   "ws_injection",
		Payload:     "hello",
		ProbeConfig: baseProbeConfig(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.VulnType != "websocket" {
		t.Fatalf("expected vuln_type websocket, got %s", result.VulnType)
	}

	m, ok := result.Measurements.(WebSocketMeasurements)
	if !ok {
		t.Fatal("expected WebSocketMeasurements")
	}
	if !m.UpgradeSuccess {
		t.Fatal("expected upgrade to succeed")
	}
	if m.UpgradeStatus != 101 {
		t.Fatalf("expected status 101, got %d", m.UpgradeStatus)
	}
	if m.FramesSent < 1 {
		t.Fatal("expected at least 1 frame sent")
	}
}

func TestWebSocket_OriginCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Custom handler that accepts all origins (permissive server)
	ts := newTestServer(t, wsEchoHandler())

	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws"

	result, err := VerifyWebSocket(WebSocketConfig{
		URL:         wsURL,
		Technique:   "ws_origin_check",
		ProbeConfig: baseProbeConfig(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(WebSocketMeasurements)
	if !ok {
		t.Fatal("expected WebSocketMeasurements")
	}
	if len(m.OriginResults) != 3 {
		t.Fatalf("expected 3 origin results, got %d", len(m.OriginResults))
	}
}

func TestWebSocket_Hijack(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t, wsEchoHandler())

	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws"

	result, err := VerifyWebSocket(WebSocketConfig{
		URL:         wsURL,
		Technique:   "ws_hijack",
		ProbeConfig: baseProbeConfig(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(WebSocketMeasurements)
	if !ok {
		t.Fatal("expected WebSocketMeasurements")
	}
	// Our echo handler accepts all origins, so hijack should succeed
	if !m.UpgradeSuccess {
		t.Fatal("expected upgrade to succeed with evil origin on permissive server")
	}
}

func TestWSHandshake_RawTCP(t *testing.T) {
	// Simple TCP listener that handles WS handshake manually
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		var wsKey string
		for {
			line, err := reader.ReadString('\n')
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
			if strings.HasPrefix(line, "Sec-WebSocket-Key:") {
				wsKey = strings.TrimSpace(strings.TrimPrefix(line, "Sec-WebSocket-Key:"))
			}
		}

		accept := computeWSAccept(wsKey)
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	}()

	addr := listener.Addr().String()
	conn, statusCode, elapsed, err := wsHandshake("ws://"+addr+"/ws", "http://localhost", nil, 5, false)
	if err != nil {
		t.Fatalf("handshake error: %v", err)
	}
	if conn != nil {
		conn.Close()
	}
	if statusCode != 101 {
		t.Fatalf("expected status 101, got %d", statusCode)
	}
	if elapsed < 0 {
		t.Fatalf("expected elapsed >= 0, got %d", elapsed)
	}
}

func TestIntegration_WebSocket_Malformed101Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	// Fake server that returns bare 101 without required WS headers
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
		}
		// Return bare 101 without Upgrade/Connection/Accept headers
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"))
	}()

	addr := ln.Addr().String()
	conn, statusCode, _, hsErr := wsHandshake("ws://"+addr+"/ws", "http://localhost", nil, 5, false)
	if conn != nil {
		conn.Close()
	}
	if statusCode != 101 {
		t.Fatalf("expected status 101, got %d", statusCode)
	}
	if hsErr == nil {
		t.Fatal("expected error for malformed 101 without WS headers")
	}
	if !strings.Contains(hsErr.Error(), "handshake") {
		t.Fatalf("expected handshake error, got: %v", hsErr)
	}
}

func TestIntegration_WebSocket_Malformed101_UpgradeSuccessFalse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	// Server sends bare 101 without required WebSocket headers.
	// VerifyWebSocket must report UpgradeSuccess=false for this.
	bare101Handler := func(conns int) net.Listener {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for i := 0; i < conns; i++ {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil || strings.TrimSpace(line) == "" {
						break
					}
				}
				conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"))
				conn.Close()
			}
		}()
		return ln
	}

	// ws_injection needs 2 connections (baseline HTTP + WS upgrade)
	ln := bare101Handler(2)
	addr := ln.Addr().String()

	result, err := VerifyWebSocket(WebSocketConfig{
		URL:         "ws://" + addr + "/ws",
		Technique:   "ws_injection",
		Payload:     "test",
		ProbeConfig: baseProbeConfig(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := result.Measurements.(WebSocketMeasurements)
	if m.UpgradeSuccess {
		t.Fatal("expected UpgradeSuccess=false for malformed 101 without WS headers")
	}
	if m.UpgradeStatus != 101 {
		t.Fatalf("expected UpgradeStatus=101, got %d", m.UpgradeStatus)
	}
}
