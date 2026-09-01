package verify

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path"
	"strings"
	"time"

	"github.com/srank/ensphere/internal/evidence"
)

// fileUploadBuild is the concrete, inert upload a technique constructs.
type fileUploadBuild struct {
	filename     string
	content      string // raw bytes to send (may be binary, e.g. a zip)
	mimeType     string
	construction string // neutral name of the construction used
	contentDesc  string // human-readable description for the measurement record
}

const benignUploadText = "ensphere_upload_test"

// buildFileUpload constructs the inert upload for a technique. Every build is
// benign: no executable code, no payload that runs anywhere. The technique name
// describes what file-type control is being probed; the construction field
// records how the file was built.
func buildFileUpload(technique, baseFilename string) (fileUploadBuild, error) {
	base := baseFilename
	if strings.TrimSpace(base) == "" {
		base = "ensphere-upload"
	}
	stem := strings.TrimSuffix(base, path.Ext(base))
	ext := strings.TrimPrefix(path.Ext(base), ".")
	if ext == "" {
		ext = "php"
	}
	switch technique {
	case "extension_bypass":
		// Double extension: an image extension in front of the original one.
		fn := stem + ".jpg." + ext
		return fileUploadBuild{filename: fn, content: benignUploadText, mimeType: "image/jpeg",
			construction: "double_extension", contentDesc: benignUploadText}, nil
	case "mime_bypass":
		// Non-image bytes declared with an image content type.
		return fileUploadBuild{filename: base, content: benignUploadText, mimeType: "image/png",
			construction: "nonimage_bytes_image_content_type", contentDesc: benignUploadText}, nil
	case "content_type_mismatch":
		// Image bytes declared with text/html.
		return fileUploadBuild{filename: base, content: "GIF89a", mimeType: "text/html",
			construction: "image_bytes_html_content_type", contentDesc: "GIF89a header bytes"}, nil
	case "polyglot_file":
		// Valid GIF89a header followed by benign text.
		return fileUploadBuild{filename: stem + ".gif", content: "GIF89a" + benignUploadText, mimeType: "image/gif",
			construction: "gif89a_polyglot", contentDesc: "GIF89a header + benign text"}, nil
	case "zip_path_traversal":
		// In-memory zip whose single entry name contains a traversal segment.
		entryName := "../ensphere-zip-slip.txt"
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, err := zw.Create(entryName)
		if err != nil {
			return fileUploadBuild{}, fmt.Errorf("build zip: %w", err)
		}
		if _, err := w.Write([]byte(benignUploadText)); err != nil {
			return fileUploadBuild{}, fmt.Errorf("write zip entry: %w", err)
		}
		if err := zw.Close(); err != nil {
			return fileUploadBuild{}, fmt.Errorf("close zip: %w", err)
		}
		return fileUploadBuild{filename: stem + ".zip", content: buf.String(), mimeType: "application/zip",
			construction: "zip_slip", contentDesc: "zip with entry name " + entryName}, nil
	default:
		return fileUploadBuild{}, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: extension_bypass, mime_bypass, content_type_mismatch, polyglot_file, zip_path_traversal", technique)}
	}
}

// FileUploadConfig holds configuration for file upload vulnerability verification.
type FileUploadConfig struct {
	URL       string
	FieldName string // form field name (default: "file")
	Filename  string // test filename (e.g., "shell.php.jpg")
	Content   string // file content (default: "ensphere_upload_test")
	MIMEType  string // Content-Type for the file part
	VerifyURL string // optional: GET this URL after upload to check accessibility
	Technique string
	Method    string // default: POST
	ProbeConfig
}

// fileUploadTechniqueRisk maps each file upload technique to its risk level.
var fileUploadTechniqueRisk = map[string]int{
	"extension_bypass":      3,
	"mime_bypass":           3,
	"content_type_mismatch": 3,
	"polyglot_file":         4,
	"zip_path_traversal":    4,
}

// MultipartHTTPProbe sends a multipart file upload request and captures timing + response hash.
func MultipartHTTPProbe(method, url, fieldName, filename, content, mimeType string,
	headers map[string]string, timeoutSec int, inScope ...[]string) ProbeResponse {
	scopePatterns, enforceScope := optionalScope(inScope)
	if enforceScope {
		if err := CheckScope(url, scopePatterns); err != nil {
			return ProbeResponse{Error: err}
		}
	}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, fieldName, filename))
	h.Set("Content-Type", mimeType)
	part, err := writer.CreatePart(h)
	if err != nil {
		return ProbeResponse{Error: fmt.Errorf("create part: %w", err)}
	}
	part.Write([]byte(content))
	writer.Close()

	client := scopedHTTPClient(timeoutSec, scopePatterns, enforceScope, true)
	req, err := http.NewRequest(method, url, &buf)
	if err != nil {
		return ProbeResponse{Error: fmt.Errorf("build request: %w", err)}
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		return ProbeResponse{ElapsedMs: elapsed, Error: fmt.Errorf("request failed: %w", err)}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10 MB max
	if err != nil {
		return ProbeResponse{
			StatusCode: resp.StatusCode,
			ElapsedMs:  elapsed,
			Headers:    resp.Header,
			Error:      fmt.Errorf("read body: %w", err),
		}
	}

	bodyStr := string(respBody)
	hash := fmt.Sprintf("%x", sha256.Sum256(respBody))

	return ProbeResponse{
		StatusCode: resp.StatusCode,
		Body:       bodyStr,
		BodyHash:   hash,
		ElapsedMs:  elapsed,
		Headers:    resp.Header,
	}
}

// VerifyFileUpload runs the file upload vulnerability verification probe.
func VerifyFileUpload(cfg FileUploadConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	risk, ok := fileUploadTechniqueRisk[cfg.Technique]
	if !ok {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: extension_bypass, mime_bypass, content_type_mismatch, polyglot_file, zip_path_traversal", cfg.Technique)}
	}

	if err := CheckMaxRisk(risk, cfg.MaxRisk); err != nil {
		return nil, err
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

	return verifyFileUploadProbe(cfg, throttle, timer, ew)
}

func verifyFileUploadProbe(cfg FileUploadConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	probeCount := 0

	build, err := buildFileUpload(cfg.Technique, cfg.Filename)
	if err != nil {
		return nil, err
	}

	// Upload probe
	throttle.Wait()
	probeCount++
	uploadResp := MultipartHTTPProbe(cfg.Method, cfg.URL, cfg.FieldName, build.filename, build.content, build.mimeType, cfg.Headers, cfg.TimeoutSec, cfg.InScope)
	if uploadResp.Error != nil {
		return nil, fmt.Errorf("upload probe: %w", uploadResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[UPLOAD] status=%d hash=%s\n", uploadResp.StatusCode, uploadResp.BodyHash[:16])
	writeEvidence(ew, "file_upload", cfg.Technique, cfg.URL, cfg.FieldName, uploadResp.StatusCode,
		fmt.Sprintf("%dms", uploadResp.ElapsedMs), "probe", fmt.Sprintf("construction=%s filename=%s mime=%s", build.construction, build.filename, build.mimeType))

	filenameInResponse := strings.Contains(uploadResp.Body, build.filename)
	uploadAccepted := uploadResp.StatusCode >= 200 && uploadResp.StatusCode < 300

	uploadRound := RoundResult{
		StatusCode: uploadResp.StatusCode,
		ElapsedMs:  uploadResp.ElapsedMs,
		BodyHash:   uploadResp.BodyHash,
		BodyLength: len(uploadResp.Body),
	}

	snippet := uploadResp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	var verifyRound *RoundResult
	var verifyAccessible *bool

	// If VerifyURL provided, check if uploaded file is accessible
	if cfg.VerifyURL != "" {
		if err := CheckScope(cfg.VerifyURL, cfg.InScope); err != nil {
			return nil, fmt.Errorf("verify-url scope check: %w", err)
		}
		throttle.Wait()
		probeCount++
		verifyResp := HTTPProbeNoRedirect("GET", cfg.VerifyURL, "", cfg.Headers, cfg.TimeoutSec, cfg.InScope)
		if verifyResp.Error != nil {
			fmt.Fprintf(os.Stderr, "[VERIFY] error: %v\n", verifyResp.Error)
		} else {
			fmt.Fprintf(os.Stderr, "[VERIFY] status=%d hash=%s\n", verifyResp.StatusCode, verifyResp.BodyHash[:16])
			writeEvidence(ew, "file_upload", cfg.Technique, cfg.VerifyURL, cfg.FieldName, verifyResp.StatusCode,
				fmt.Sprintf("%dms", verifyResp.ElapsedMs), "verify", fmt.Sprintf("verify URL check status=%d", verifyResp.StatusCode))
			vr := RoundResult{
				StatusCode: verifyResp.StatusCode,
				ElapsedMs:  verifyResp.ElapsedMs,
				BodyHash:   verifyResp.BodyHash,
				BodyLength: len(verifyResp.Body),
			}
			verifyRound = &vr
			accessible := verifyResp.StatusCode == 200
			verifyAccessible = &accessible
		}
	}

	return &ProbeResult{
		VulnType:   "file_upload",
		Technique:  cfg.Technique,
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: FileUploadMeasurements{
			Technique:          cfg.Technique,
			Construction:       build.construction,
			UploadProbe:        uploadRound,
			FilenameInResponse: filenameInResponse,
			UploadAccepted:     uploadAccepted,
			VerifyProbe:        verifyRound,
			VerifyAccessible:   verifyAccessible,
			FilenameSent:       build.filename,
			MIMETypeSent:       build.mimeType,
			ContentSent:        build.contentDesc,
			ResponseSnippet:    snippet,
		},
	}, nil
}
