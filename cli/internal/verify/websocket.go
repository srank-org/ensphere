package verify

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/srank/ensphere/internal/evidence"
)

// WebSocketConfig holds configuration for WebSocket verification.
type WebSocketConfig struct {
	URL       string
	Technique string // ws_injection | ws_hijack | ws_origin_check
	Payload   string
	TLSVerify bool // verify the server certificate (default true)
	ProbeConfig
}

var validWSTechniques = map[string]bool{
	"ws_injection": true, "ws_hijack": true, "ws_origin_check": true,
}

// wsGUID is the WebSocket magic GUID used in Sec-WebSocket-Accept computation.
const wsGUID = "258EAFA5-E914-47DA-95CA-5E5AB5DC85B8"

// VerifyWebSocket runs the WebSocket security verification probe.
func VerifyWebSocket(cfg WebSocketConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if !validWSTechniques[cfg.Technique] {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: ws_injection, ws_hijack, ws_origin_check", cfg.Technique)}
	}

	timer := NewTimer()
	throttle := NewThrottle(cfg.ThrottleMs)

	var ew *evidence.Writer
	if cfg.Evidence != "" {
		var err error
		ew, err = evidence.NewWriter(cfg.Evidence)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not open evidence file: %v\n", err)
		} else {
			defer ew.Close()
		}
	}

	probeCount := 0

	switch cfg.Technique {
	case "ws_injection":
		return wsInjection(cfg, timer, throttle, ew, &probeCount)
	case "ws_hijack":
		return wsHijack(cfg, timer, throttle, ew, &probeCount)
	case "ws_origin_check":
		return wsOriginCheck(cfg, timer, throttle, ew, &probeCount)
	default:
		return nil, fmt.Errorf("unsupported technique %q", cfg.Technique)
	}
}

func wsInjection(cfg WebSocketConfig, timer *Timer, throttle *Throttle, ew *evidence.Writer, probeCount *int) (*ProbeResult, error) {
	// HTTP baseline
	throttle.Wait()
	*probeCount++

	// Convert ws:// to http:// for baseline
	httpURL := strings.Replace(cfg.URL, "ws://", "http://", 1)
	httpURL = strings.Replace(httpURL, "wss://", "https://", 1)
	baselineResp := HTTPProbe("GET", httpURL, "", cfg.Headers, cfg.TimeoutSec, cfg.InScope)
	baseline := RoundResult{
		StatusCode: baselineResp.StatusCode,
		ElapsedMs:  baselineResp.ElapsedMs,
		BodyHash:   baselineResp.BodyHash,
		BodyLength: len(baselineResp.Body),
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d %dms\n", baselineResp.StatusCode, baselineResp.ElapsedMs)
	writeEvidence(ew, "websocket", cfg.Technique, cfg.URL, "", baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "HTTP GET baseline")

	// WebSocket upgrade
	throttle.Wait()
	*probeCount++
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	origin := fmt.Sprintf("http://%s", parsed.Hostname())

	conn, statusCode, elapsed, err := wsHandshake(cfg.URL, origin, cfg.Headers, cfg.TimeoutSec, cfg.TLSVerify)
	upgradeSuccess := statusCode == 101 && err == nil
	fmt.Fprintf(os.Stderr, "[WS UPGRADE] status=%d %dms success=%v\n", statusCode, elapsed, upgradeSuccess)
	writeEvidence(ew, "websocket", cfg.Technique, cfg.URL, "", statusCode,
		fmt.Sprintf("%dms", elapsed), "probe", "WebSocket upgrade attempt")

	framesSent := 0
	framesReceived := 0
	var probeRounds []RoundResult

	if err == nil && upgradeSuccess && conn != nil {
		defer conn.Close()

		// Send payload as text frame
		if cfg.Payload != "" {
			if writeErr := wsWriteTextFrame(conn, cfg.Payload); writeErr == nil {
				framesSent++
			}

			// Read response frame
			_ = conn.SetReadDeadline(time.Now().Add(time.Duration(cfg.TimeoutSec) * time.Second))
			if _, readErr := wsReadFrame(conn); readErr == nil {
				framesReceived++
			}
		}

		probeRounds = append(probeRounds, RoundResult{
			StatusCode: statusCode,
			ElapsedMs:  elapsed,
		})
	} else {
		if conn != nil {
			conn.Close()
		}
		probeRounds = append(probeRounds, RoundResult{
			StatusCode: statusCode,
			ElapsedMs:  elapsed,
		})
	}

	return &ProbeResult{
		VulnType:   "websocket",
		Technique:  cfg.Technique,
		StartedAt:  timer.StartedAt(),
		ProbeCount: *probeCount,
		Duration:   timer.Elapsed(),
		Measurements: WebSocketMeasurements{
			Technique:      cfg.Technique,
			UpgradeStatus:  statusCode,
			UpgradeSuccess: upgradeSuccess,
			Baseline:       baseline,
			ProbeRounds:    probeRounds,
			FramesSent:     framesSent,
			FramesReceived: framesReceived,
			PayloadUsed:    cfg.Payload,
		},
	}, nil
}

func wsHijack(cfg WebSocketConfig, timer *Timer, throttle *Throttle, ew *evidence.Writer, probeCount *int) (*ProbeResult, error) {
	throttle.Wait()
	*probeCount++

	conn, statusCode, elapsed, hsErr := wsHandshake(cfg.URL, "http://evil.example.com", cfg.Headers, cfg.TimeoutSec, cfg.TLSVerify)
	if conn != nil {
		conn.Close()
	}

	upgradeSuccess := statusCode == 101 && hsErr == nil
	fmt.Fprintf(os.Stderr, "[WS HIJACK] status=%d %dms success=%v\n", statusCode, elapsed, upgradeSuccess)
	writeEvidence(ew, "websocket", cfg.Technique, cfg.URL, "", statusCode,
		fmt.Sprintf("%dms", elapsed), "probe", "evil origin WebSocket upgrade")

	return &ProbeResult{
		VulnType:   "websocket",
		Technique:  cfg.Technique,
		StartedAt:  timer.StartedAt(),
		ProbeCount: *probeCount,
		Duration:   timer.Elapsed(),
		Measurements: WebSocketMeasurements{
			Technique:      cfg.Technique,
			UpgradeStatus:  statusCode,
			UpgradeSuccess: upgradeSuccess,
			ProbeRounds: []RoundResult{{
				StatusCode: statusCode,
				ElapsedMs:  elapsed,
			}},
			PayloadUsed: "Origin: http://evil.example.com",
		},
	}, nil
}

func wsOriginCheck(cfg WebSocketConfig, timer *Timer, throttle *Throttle, ew *evidence.Writer, probeCount *int) (*ProbeResult, error) {
	type originTest struct {
		name   string
		origin string // empty means omit Origin header
	}

	tests := []originTest{
		{name: "no_origin", origin: ""},
		{name: "null_origin", origin: "null"},
		{name: "evil_origin", origin: "http://evil.example.com"},
	}

	var results []OriginCheckResult
	for _, test := range tests {
		throttle.Wait()
		*probeCount++

		conn, statusCode, elapsed, hsErr := wsHandshake(cfg.URL, test.origin, cfg.Headers, cfg.TimeoutSec, cfg.TLSVerify)
		if conn != nil {
			conn.Close()
		}

		upgradeSuccess := statusCode == 101 && hsErr == nil
		results = append(results, OriginCheckResult{
			Origin:         test.name,
			UpgradeStatus:  statusCode,
			UpgradeSuccess: upgradeSuccess,
			ElapsedMs:      elapsed,
		})
		fmt.Fprintf(os.Stderr, "[ORIGIN %s] status=%d %dms success=%v\n", test.name, statusCode, elapsed, upgradeSuccess)
		writeEvidence(ew, "websocket", cfg.Technique, cfg.URL, "", statusCode,
			fmt.Sprintf("%dms", elapsed), "probe", fmt.Sprintf("origin check: %s", test.name))
	}

	return &ProbeResult{
		VulnType:   "websocket",
		Technique:  cfg.Technique,
		StartedAt:  timer.StartedAt(),
		ProbeCount: *probeCount,
		Duration:   timer.Elapsed(),
		Measurements: WebSocketMeasurements{
			Technique:     cfg.Technique,
			OriginResults: results,
			PayloadUsed:   "origin_check",
		},
	}, nil
}

// wsHandshake performs a raw TCP WebSocket upgrade handshake.
// origin="" means omit the Origin header entirely.
func wsHandshake(rawURL string, origin string, extraHeaders map[string]string, timeoutSec int, tlsVerify bool) (net.Conn, int, int64, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("parse URL: %w", err)
	}

	host := parsed.Host
	useTLS := parsed.Scheme == "wss" || parsed.Scheme == "https"

	if !strings.Contains(host, ":") {
		if useTLS {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	path := parsed.RequestURI()
	if path == "" {
		path = "/"
	}

	timeout := time.Duration(timeoutSec) * time.Second
	start := time.Now()

	var conn net.Conn
	if useTLS {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", host, &tls.Config{
			ServerName: parsed.Hostname(),
			// Protocol probing only: the WebSocket upgrade handshake is what is
			// being measured. --tls-verify=false allows internal or self-signed
			// certs; the default verifies.
			InsecureSkipVerify: !tlsVerify,
		})
	} else {
		conn, err = net.DialTimeout("tcp", host, timeout)
	}
	if err != nil {
		return nil, 0, time.Since(start).Milliseconds(), fmt.Errorf("connect: %w", err)
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))

	wsKey := generateWSKey()

	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&req, "Host: %s\r\n", parsed.Host)
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\n", wsKey)
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	if origin != "" {
		fmt.Fprintf(&req, "Origin: %s\r\n", origin)
	}

	skip := map[string]bool{"host": true, "upgrade": true, "connection": true,
		"sec-websocket-key": true, "sec-websocket-version": true, "origin": true}
	for k, v := range extraHeaders {
		if !skip[strings.ToLower(k)] {
			fmt.Fprintf(&req, "%s: %s\r\n", k, v)
		}
	}
	req.WriteString("\r\n")

	_, err = conn.Write([]byte(req.String()))
	if err != nil {
		conn.Close()
		return nil, 0, time.Since(start).Milliseconds(), fmt.Errorf("write: %w", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		conn.Close()
		return nil, 0, elapsed, fmt.Errorf("read status: %w", err)
	}

	statusCode := parseHTTPStatus(statusLine)

	// Read remaining headers and validate WebSocket upgrade
	var hasUpgrade, hasConnection bool
	var serverAccept string
	for {
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
		headerLine := strings.TrimSpace(line)
		lower := strings.ToLower(headerLine)
		if strings.HasPrefix(lower, "upgrade:") {
			val := strings.TrimSpace(headerLine[len("upgrade:"):])
			hasUpgrade = strings.EqualFold(val, "websocket")
		}
		if strings.HasPrefix(lower, "connection:") {
			val := strings.TrimSpace(headerLine[len("connection:"):])
			for _, token := range strings.Split(val, ",") {
				if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
					hasConnection = true
					break
				}
			}
		}
		if strings.HasPrefix(lower, "sec-websocket-accept:") {
			serverAccept = strings.TrimSpace(headerLine[len("sec-websocket-accept:"):])
		}
	}

	if statusCode != 101 {
		conn.Close()
		return nil, statusCode, elapsed, fmt.Errorf("upgrade failed: status %d", statusCode)
	}

	if !hasUpgrade || !hasConnection {
		conn.Close()
		return nil, statusCode, elapsed, fmt.Errorf("invalid websocket handshake: missing required headers (upgrade=%v, connection=%v)", hasUpgrade, hasConnection)
	}

	expectedAccept := computeWSAccept(wsKey)
	if serverAccept != expectedAccept {
		conn.Close()
		return nil, statusCode, elapsed, fmt.Errorf("invalid websocket handshake: Sec-WebSocket-Accept mismatch (got %q, want %q)", serverAccept, expectedAccept)
	}

	return conn, statusCode, elapsed, nil
}

// parseHTTPStatus extracts the status code from an HTTP status line.
func parseHTTPStatus(line string) int {
	// "HTTP/1.1 101 Switching Protocols\r\n"
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 {
		return 0
	}
	var code int
	fmt.Sscanf(parts[1], "%d", &code)
	return code
}

// generateWSKey generates a random Sec-WebSocket-Key value.
func generateWSKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// computeWSAccept computes the Sec-WebSocket-Accept value for the given key.
func computeWSAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// wsWriteTextFrame writes a masked WebSocket text frame.
func wsWriteTextFrame(conn net.Conn, payload string) error {
	data := []byte(payload)
	payloadLen := len(data)

	// Build frame header
	var frame []byte
	frame = append(frame, 0x81) // FIN=1, opcode=1 (text)

	if payloadLen < 126 {
		frame = append(frame, byte(0x80|payloadLen)) // MASK=1
	} else if payloadLen <= 65535 {
		frame = append(frame, 0xFE) // MASK=1, 126
		frame = append(frame, byte(payloadLen>>8), byte(payloadLen))
	} else {
		return fmt.Errorf("payload too large for single frame")
	}

	// 4-byte masking key
	maskKey := make([]byte, 4)
	_, _ = rand.Read(maskKey)
	frame = append(frame, maskKey...)

	// XOR-masked payload
	masked := make([]byte, payloadLen)
	for i, b := range data {
		masked[i] = b ^ maskKey[i%4]
	}
	frame = append(frame, masked...)

	_, err := conn.Write(frame)
	return err
}

// wsReadFrame reads a single WebSocket frame from the connection.
func wsReadFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := conn.Read(header); err != nil {
		return nil, err
	}

	payloadLen := int(header[1] & 0x7F)
	masked := header[1]&0x80 != 0

	if payloadLen == 126 {
		ext := make([]byte, 2)
		if _, err := conn.Read(ext); err != nil {
			return nil, err
		}
		payloadLen = int(ext[0])<<8 | int(ext[1])
	} else if payloadLen == 127 {
		ext := make([]byte, 8)
		if _, err := conn.Read(ext); err != nil {
			return nil, err
		}
		payloadLen = int(ext[4])<<24 | int(ext[5])<<16 | int(ext[6])<<8 | int(ext[7])
	}

	const maxWSPayloadSize = 16 * 1024 * 1024 // 16 MB
	if payloadLen > maxWSPayloadSize {
		return nil, fmt.Errorf("websocket frame too large: %d bytes (max %d)", payloadLen, maxWSPayloadSize)
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := conn.Read(maskKey); err != nil {
			return nil, err
		}
	}

	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		n := 0
		for n < payloadLen {
			read, err := conn.Read(payload[n:])
			if err != nil {
				return nil, err
			}
			n += read
		}
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return payload, nil
}
