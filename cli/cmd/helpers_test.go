package cmd

import (
	"errors"
	"testing"

	"github.com/srank-org/ensphere/internal/verify"
)

func TestParseHeadersAllowsColonInValue(t *testing.T) {
	headers, err := parseHeaders([]string{"X-Trace: abc:def:ghi", "Authorization: Bearer token"})
	if err != nil {
		t.Fatalf("parseHeaders: %v", err)
	}
	if headers["X-Trace"] != "abc:def:ghi" {
		t.Fatalf("unexpected X-Trace value: %q", headers["X-Trace"])
	}
	if headers["Authorization"] != "Bearer token" {
		t.Fatalf("unexpected Authorization value: %q", headers["Authorization"])
	}
}

func TestParseHeadersRejectsMalformed(t *testing.T) {
	if _, err := parseHeaders([]string{"MissingColon"}); !errors.Is(err, errUsage) {
		t.Fatalf("expected usage error, got %v", err)
	}
	if _, err := parseHeaders([]string{": value"}); !errors.Is(err, errUsage) {
		t.Fatalf("expected usage error for empty key, got %v", err)
	}
}

func TestExitForVerifyError(t *testing.T) {
	if got := exitForVerifyError(&verify.ScopeError{Msg: "out of scope"}); got != 2 {
		t.Fatalf("expected scope exit 2, got %d", got)
	}
	if got := exitForVerifyError(errUsage); got != 2 {
		t.Fatalf("expected usage exit 2, got %d", got)
	}
	if got := exitForVerifyError(errors.New("boom")); got != 3 {
		t.Fatalf("expected runtime exit 3, got %d", got)
	}
}
