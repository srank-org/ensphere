package verify

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/srank-org/ensphere/internal/evidence"
)

const maxUploadSizeBytes = 104857600 // 100 MB

// LimitsConfig holds configuration for size and volume limit measurement.
type LimitsConfig struct {
	URL       string
	Technique string // pagination | upload_size | response_size
	Method    string // default GET; pagination/response_size honor it
	Body      string // optional JSON body for pagination POST
	Param     string // pagination parameter name
	Values    []int  // pagination values (max 10, non-negative)
	Sizes     []int  // upload sizes in bytes (max 5, each <= 100 MB)
	Field     string // upload multipart field name (default "file")
	Token     string
	ProbeConfig
}

// LimitsPaginationRound records one pagination request.
type LimitsPaginationRound struct {
	Value         int    `json:"value"`
	StatusCode    int    `json:"status_code"`
	ElapsedMs     int64  `json:"elapsed_ms"`
	BodyBytes     int    `json:"body_bytes"`
	BodyHash      string `json:"body_hash"`
	ItemCount     *int   `json:"item_count"`
	ContentLength string `json:"content_length,omitempty"`
}

// LimitsUploadRound records one upload-size request.
type LimitsUploadRound struct {
	SizeBytes     int    `json:"size_bytes"`
	StatusCode    int    `json:"status_code"`
	ElapsedMs     int64  `json:"elapsed_ms"`
	BodyHash      string `json:"body_hash"`
	ResponseBytes int    `json:"response_bytes"`
	// ConnectionClosed is true when the server closed the connection before
	// the whole body was sent or the response fully read: StatusCode is the
	// answer it sent first, or 0 when it sent none.
	ConnectionClosed bool `json:"connection_closed,omitempty"`
}

// LimitsResponseRound records a single response-size measurement.
type LimitsResponseRound struct {
	BodyBytes           int    `json:"body_bytes"`
	ContentLengthHeader string `json:"content_length_header,omitempty"`
	ContentEncoding     string `json:"content_encoding,omitempty"`
	ElapsedMs           int64  `json:"elapsed_ms"`
	BodyHash            string `json:"body_hash"`
}

// LimitsMeasurements holds size and volume limit probe measurements.
type LimitsMeasurements struct {
	Technique  string                  `json:"technique"`
	Pagination []LimitsPaginationRound `json:"pagination,omitempty"`
	Upload     []LimitsUploadRound     `json:"upload,omitempty"`
	Response   *LimitsResponseRound    `json:"response,omitempty"`
}

// VerifyLimits runs the size and volume limit measurement probe.
func VerifyLimits(cfg LimitsConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}
	if err := CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
	}
	if cfg.Method == "" {
		cfg.Method = "GET"
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

	switch cfg.Technique {
	case "pagination":
		return verifyLimitsPagination(cfg, throttle, timer, ew)
	case "upload_size":
		return verifyLimitsUploadSize(cfg, throttle, timer, ew)
	case "response_size":
		return verifyLimitsResponseSize(cfg, throttle, timer, ew)
	default:
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: pagination, upload_size, response_size", cfg.Technique)}
	}
}

func authHeaders(base map[string]string, token string) map[string]string {
	headers := make(map[string]string)
	for k, v := range base {
		headers[k] = v
	}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	return headers
}

func verifyLimitsPagination(cfg LimitsConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	if cfg.Param == "" {
		return nil, &ScopeError{Msg: "pagination requires --param"}
	}
	if len(cfg.Values) == 0 {
		return nil, &ScopeError{Msg: "pagination requires --values (refusing to run without explicit values)"}
	}
	if len(cfg.Values) > 10 {
		return nil, &ScopeError{Msg: "pagination allows at most 10 values"}
	}
	for _, v := range cfg.Values {
		if v < 0 {
			return nil, &ScopeError{Msg: "pagination values must be non-negative integers"}
		}
	}

	headers := authHeaders(cfg.Headers, cfg.Token)
	bodyIsJSON := cfg.Method != "GET" && looksLikeJSON(cfg.Body)
	if bodyIsJSON {
		headers["Content-Type"] = "application/json"
	}

	var rounds []LimitsPaginationRound
	for _, value := range cfg.Values {
		throttle.Wait()

		reqURL := cfg.URL
		body := cfg.Body
		if bodyIsJSON {
			b, err := setJSONField(cfg.Body, cfg.Param, value)
			if err != nil {
				return nil, fmt.Errorf("set json field: %w", err)
			}
			body = b
		} else {
			u, err := setQueryParam(cfg.URL, cfg.Param, strconv.Itoa(value))
			if err != nil {
				return nil, fmt.Errorf("set query param: %w", err)
			}
			reqURL = u
		}

		resp := HTTPProbe(cfg.Method, reqURL, body, headers, cfg.TimeoutSec, cfg.InScope)
		if resp.Error != nil {
			return nil, fmt.Errorf("pagination probe (value=%d): %w", value, resp.Error)
		}

		round := LimitsPaginationRound{
			Value:      value,
			StatusCode: resp.StatusCode,
			ElapsedMs:  resp.ElapsedMs,
			BodyBytes:  len(resp.Body),
			BodyHash:   fmt.Sprintf("%x", sha256.Sum256([]byte(resp.Body))),
			ItemCount:  topLevelItemCount([]byte(resp.Body)),
		}
		if resp.Headers != nil {
			round.ContentLength = resp.Headers.Get("Content-Length")
		}
		rounds = append(rounds, round)

		fmt.Fprintf(os.Stderr, "[LIMITS pagination %s=%d] status=%d bytes=%d items=%s\n", cfg.Param, value, resp.StatusCode, len(resp.Body), itemCountString(round.ItemCount))
		writeEvidence(ew, "limits", "pagination", cfg.URL, cfg.Param, resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "probe", fmt.Sprintf("%s=%d body_bytes=%d", cfg.Param, value, len(resp.Body)))
	}

	return &ProbeResult{
		VulnType:     "limits",
		Technique:    "pagination",
		StartedAt:    timer.StartedAt(),
		ProbeCount:   len(rounds),
		Duration:     timer.Elapsed(),
		Measurements: LimitsMeasurements{Technique: "pagination", Pagination: rounds},
	}, nil
}

func verifyLimitsUploadSize(cfg LimitsConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	if len(cfg.Sizes) == 0 {
		return nil, &ScopeError{Msg: "upload_size requires --sizes (refusing to run without explicit sizes)"}
	}
	if len(cfg.Sizes) > 5 {
		return nil, &ScopeError{Msg: "upload_size allows at most 5 sizes"}
	}
	for _, s := range cfg.Sizes {
		if s < 0 {
			return nil, &ScopeError{Msg: "upload sizes must be non-negative"}
		}
		if s > maxUploadSizeBytes {
			return nil, &ScopeError{Msg: fmt.Sprintf("upload size %d exceeds the %d-byte cap", s, maxUploadSizeBytes)}
		}
	}
	field := cfg.Field
	if field == "" {
		field = "file"
	}
	method := cfg.Method
	if method == "" || method == "GET" {
		method = "POST"
	}

	headers := authHeaders(cfg.Headers, cfg.Token)

	var rounds []LimitsUploadRound
	for _, size := range cfg.Sizes {
		throttle.Wait()
		round, err := uploadSizeProbe(cfg, method, field, size, headers)
		if err != nil {
			return nil, fmt.Errorf("upload_size probe (size=%d): %w", size, err)
		}
		rounds = append(rounds, round)
		note := fmt.Sprintf("size_bytes=%d", size)
		if round.ConnectionClosed {
			note += " connection_closed=true"
		}
		fmt.Fprintf(os.Stderr, "[LIMITS upload_size=%d] status=%d closed=%t\n", size, round.StatusCode, round.ConnectionClosed)
		writeEvidence(ew, "limits", "upload_size", cfg.URL, field, round.StatusCode,
			fmt.Sprintf("%dms", round.ElapsedMs), "probe", note)
	}

	return &ProbeResult{
		VulnType:     "limits",
		Technique:    "upload_size",
		StartedAt:    timer.StartedAt(),
		ProbeCount:   len(rounds),
		Duration:     timer.Elapsed(),
		Measurements: LimitsMeasurements{Technique: "upload_size", Upload: rounds},
	}, nil
}

// uploadSizeProbe streams a multipart body of `size` random bytes, declaring
// its exact Content-Length and Expect: 100-continue as a large real upload
// does, so a server that caps on the headers can refuse before any body is
// sent and its answer is not lost to a connection it resets mid-upload.
func uploadSizeProbe(cfg LimitsConfig, method, field string, size int, headers map[string]string) (LimitsUploadRound, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return LimitsUploadRound{}, err
	}

	var prologue, epilogue bytes.Buffer
	writer := multipart.NewWriter(&prologue)
	if _, err := writer.CreateFormFile(field, fmt.Sprintf("ensphere-limit-%d.bin", size)); err != nil {
		return LimitsUploadRound{}, fmt.Errorf("build multipart body: %w", err)
	}
	// The part's bytes stream between the two buffers; closing the writer
	// against the second buffer yields only the closing boundary.
	writerForEpilogue := multipart.NewWriter(&epilogue)
	if err := writerForEpilogue.SetBoundary(writer.Boundary()); err != nil {
		return LimitsUploadRound{}, fmt.Errorf("build multipart body: %w", err)
	}
	if err := writerForEpilogue.Close(); err != nil {
		return LimitsUploadRound{}, fmt.Errorf("build multipart body: %w", err)
	}
	body := io.MultiReader(bytes.NewReader(prologue.Bytes()), io.LimitReader(rand.Reader, int64(size)), bytes.NewReader(epilogue.Bytes()))

	client := scopedHTTPClient(cfg.TimeoutSec, cfg.InScope, len(cfg.InScope) > 0, false)
	req, err := http.NewRequest(method, cfg.URL, body)
	if err != nil {
		return LimitsUploadRound{}, fmt.Errorf("build request: %w", err)
	}
	req.ContentLength = int64(prologue.Len() + size + epilogue.Len())
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Expect", "100-continue")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		if !closedDuringUpload(err) {
			return LimitsUploadRound{}, fmt.Errorf("request failed: %w", err)
		}
		return LimitsUploadRound{
			SizeBytes:        size,
			ElapsedMs:        elapsed,
			BodyHash:         fmt.Sprintf("%x", sha256.Sum256(nil)),
			ConnectionClosed: true,
		}, nil
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	round := LimitsUploadRound{
		SizeBytes:     size,
		StatusCode:    resp.StatusCode,
		ElapsedMs:     elapsed,
		BodyHash:      fmt.Sprintf("%x", sha256.Sum256(respBody)),
		ResponseBytes: len(respBody),
	}
	if readErr != nil {
		if !closedDuringUpload(readErr) {
			return LimitsUploadRound{}, fmt.Errorf("read body: %w", readErr)
		}
		round.ConnectionClosed = true
	}
	return round, nil
}

// closedDuringUpload reports whether err says the peer closed the connection
// while the body was being sent or the response read. A server that refuses
// an oversize body before consuming it commonly answers and closes, or just
// closes; both are measurements. A refused connection, a scope failure, or a
// timeout is not.
func closedDuringUpload(err error) bool {
	for _, target := range []error{io.EOF, io.ErrUnexpectedEOF, net.ErrClosed, syscall.ECONNRESET, syscall.EPIPE} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func verifyLimitsResponseSize(cfg LimitsConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	headers := authHeaders(cfg.Headers, cfg.Token)
	throttle.Wait()
	resp := HTTPProbe(cfg.Method, cfg.URL, cfg.Body, headers, cfg.TimeoutSec, cfg.InScope)
	if resp.Error != nil {
		return nil, fmt.Errorf("response_size probe: %w", resp.Error)
	}
	round := &LimitsResponseRound{
		BodyBytes: len(resp.Body),
		ElapsedMs: resp.ElapsedMs,
		BodyHash:  fmt.Sprintf("%x", sha256.Sum256([]byte(resp.Body))),
	}
	if resp.Headers != nil {
		round.ContentLengthHeader = resp.Headers.Get("Content-Length")
		round.ContentEncoding = resp.Headers.Get("Content-Encoding")
	}
	fmt.Fprintf(os.Stderr, "[LIMITS response_size] status=%d bytes=%d\n", resp.StatusCode, len(resp.Body))
	writeEvidence(ew, "limits", "response_size", cfg.URL, "", resp.StatusCode,
		fmt.Sprintf("%dms", resp.ElapsedMs), "probe", fmt.Sprintf("body_bytes=%d", len(resp.Body)))

	return &ProbeResult{
		VulnType:     "limits",
		Technique:    "response_size",
		StartedAt:    timer.StartedAt(),
		ProbeCount:   1,
		Duration:     timer.Elapsed(),
		Measurements: LimitsMeasurements{Technique: "response_size", Response: round},
	}, nil
}

// topLevelItemCount returns the length of the top-level JSON array, else the
// length of the first (lexicographically first key) top-level array-valued
// field, else nil.
func topLevelItemCount(body []byte) *int {
	var arr []json.RawMessage
	if json.Unmarshal(body, &arr) == nil {
		n := len(arr)
		return &n
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(body, &obj) == nil {
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			var a []json.RawMessage
			if json.Unmarshal(obj[k], &a) == nil {
				n := len(a)
				return &n
			}
		}
	}
	return nil
}

func itemCountString(n *int) string {
	if n == nil {
		return "null"
	}
	return strconv.Itoa(*n)
}

func looksLikeJSON(body string) bool {
	for _, r := range body {
		switch r {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

func setJSONField(body, field string, value int) (string, error) {
	obj := map[string]json.RawMessage{}
	if looksLikeJSON(body) {
		if err := json.Unmarshal([]byte(body), &obj); err != nil {
			return "", err
		}
	}
	obj[field] = json.RawMessage(strconv.Itoa(value))
	out, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func setQueryParam(rawURL, key, value string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := parsed.Query()
	q.Set(key, value)
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}
