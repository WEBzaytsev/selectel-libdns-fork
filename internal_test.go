package selectel

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// captureLogger returns a *log.Logger whose output is collected into
// the supplied buffer. Used by tests that need to assert what was
// (or was not) logged.
func captureLogger(buf *bytes.Buffer) *log.Logger {
	return log.New(buf, "", 0)
}

// logLines returns the non-empty lines written to buf.
func logLines(buf *bytes.Buffer) []string {
	raw := strings.Split(buf.String(), "\n")
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		if strings.TrimSpace(l) == "" {
			continue
		}
		out = append(out, l)
	}
	return out
}

func TestNameNormalizer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		zone string
		want string
	}{
		{"test", "zone.com", "test.zone.com."},
		{"test", "zone.com.", "test.zone.com."},
		{"test.zone.com", "zone.com", "test.zone.com."},
		{"test.zone.com.", "zone.com.", "test.zone.com."},
		{"@", "zone.com", "zone.com."},
		{"", "zone.com", "zone.com."},
		{".", "zone.com", "zone.com."},
		{"sub.test", "zone.com", "sub.test.zone.com."},
		{"a.b.c.zone.com", "zone.com", "a.b.c.zone.com."},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name+"|"+tc.zone, func(t *testing.T) {
			t.Parallel()
			got := nameNormalizer(tc.name, tc.zone)
			if got != tc.want {
				t.Fatalf("nameNormalizer(%q, %q) = %q, want %q", tc.name, tc.zone, got, tc.want)
			}
		})
	}
}

func TestLibdnsToRecord_ClampsLowTTL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		ttl  time.Duration
		want int
	}{
		{"zero TTL is clamped to 60", 0, 60},
		{"sub-minimum TTL is clamped to 60", 30 * time.Second, 60},
		{"explicit 60 stays 60", 60 * time.Second, 60},
		{"high TTL is preserved", 3600 * time.Second, 3600},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rr := libdns.RR{Type: "A", Name: "host", Data: "1.2.3.4", TTL: tc.ttl}
			rec := libdnsToRecord("zone.com", rr)
			if rec.TTL != tc.want {
				t.Fatalf("TTL = %d, want %d", rec.TTL, tc.want)
			}
		})
	}
}

func TestLibdnsToRecord_TXTValueIsQuoted(t *testing.T) {
	t.Parallel()

	rr := libdns.RR{Type: "TXT", Name: "host", Data: "hello world", TTL: 60 * time.Second}
	rec := libdnsToRecord("zone.com", rr)

	if len(rec.Records) != 1 {
		t.Fatalf("expected 1 RecordItem, got %d", len(rec.Records))
	}
	if rec.Records[0].Content != `"hello world"` {
		t.Fatalf("TXT value not quoted: got %q", rec.Records[0].Content)
	}
}

func TestLibdnsToRecord_EmptyDataReturnsZeroRecord(t *testing.T) {
	t.Parallel()

	rr := libdns.RR{Type: "A", Name: "host", Data: "", TTL: 60 * time.Second}
	rec := libdnsToRecord("zone.com", rr)
	if rec.Type != "" || rec.Name != "" || rec.TTL != 0 || len(rec.Records) != 0 {
		t.Fatalf("expected zero-value Record for empty Data, got %+v", rec)
	}
}

func TestIsConflictError(t *testing.T) {
	t.Parallel()

	conflict := &httpError{StatusCode: http.StatusConflict, Status: "Conflict", Body: "duplicate"}
	wrapped := errors.New("plain error")

	if !isConflictError(conflict) {
		t.Fatalf("expected isConflictError(conflict) == true")
	}
	if isConflictError(wrapped) {
		t.Fatalf("expected isConflictError(plain) == false")
	}
	if isConflictError(nil) {
		t.Fatalf("expected isConflictError(nil) == false")
	}

	notFound := &httpError{StatusCode: http.StatusNotFound, Status: "Not Found"}
	if isConflictError(notFound) {
		t.Fatalf("expected isConflictError(404) == false")
	}
}

func TestShouldRetryHTTPRequest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		code int
		want bool
	}{
		{"409 is not retried", &httpError{StatusCode: 409, Status: "Conflict"}, 409, false},
		{"429 is retried", &httpError{StatusCode: 429, Status: "Too Many Requests"}, 429, true},
		{"500 is retried", &httpError{StatusCode: 500, Status: "Internal Server Error"}, 500, true},
		{"502 is retried", &httpError{StatusCode: 502, Status: "Bad Gateway"}, 502, true},
		{"503 is retried", &httpError{StatusCode: 503, Status: "Service Unavailable"}, 503, true},
		{"504 is retried", &httpError{StatusCode: 504, Status: "Gateway Timeout"}, 504, true},
		{"400 is not retried", &httpError{StatusCode: 400, Status: "Bad Request"}, 400, false},
		{"timeout error is retried", errors.New("dial tcp: i/o timeout"), 0, true},
		{"connection refused is retried", errors.New("dial tcp: connection refused"), 0, true},
		{"no such host is retried", errors.New("lookup: no such host"), 0, true},
		{"random error is not retried", errors.New("something unknown"), 0, false},
		{"nil with code 0 is not retried", nil, 0, false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := shouldRetryHTTPRequest(tc.err, tc.code)
			if got != tc.want {
				t.Fatalf("shouldRetryHTTPRequest(%v, %d) = %v, want %v", tc.err, tc.code, got, tc.want)
			}
		})
	}
}

func TestEffectiveRetryConfiguration_ZeroValueUsesDefaults(t *testing.T) {
	t.Parallel()

	p := &Provider{}
	got := p.effectiveRetryConfiguration()
	want := CreateDefaultHTTPRequestRetryConfiguration()
	if got != want {
		t.Fatalf("zero-value config did not produce defaults: got %+v want %+v", got, want)
	}
}

func TestEffectiveRetryConfiguration_NonZeroIsHonoured(t *testing.T) {
	t.Parallel()

	custom := HTTPRequestRetryConfiguration{
		MaximumRetryAttempts:         0, // explicit "no retries"
		InitialRetryDelay:            500 * time.Millisecond,
		MaximumRetryDelay:            time.Second,
		ExponentialBackoffMultiplier: 1.0,
	}
	p := &Provider{HTTPRequestRetryConfiguration: custom}
	got := p.effectiveRetryConfiguration()
	if got != custom {
		t.Fatalf("custom config was overridden: got %+v want %+v", got, custom)
	}
}

func TestCalculateExponentialBackoffDelay_RespectsCap(t *testing.T) {
	t.Parallel()

	p := &Provider{}
	cfg := HTTPRequestRetryConfiguration{
		MaximumRetryAttempts:         5,
		InitialRetryDelay:            1 * time.Second,
		MaximumRetryDelay:            4 * time.Second,
		ExponentialBackoffMultiplier: 2.0,
	}

	if got := p.calculateExponentialBackoffDelay(cfg, 0); got != 1*time.Second {
		t.Fatalf("attempt 0: got %v want 1s", got)
	}
	if got := p.calculateExponentialBackoffDelay(cfg, 1); got != 2*time.Second {
		t.Fatalf("attempt 1: got %v want 2s", got)
	}
	if got := p.calculateExponentialBackoffDelay(cfg, 2); got != 4*time.Second {
		t.Fatalf("attempt 2: got %v want 4s", got)
	}
	// Attempt 3 would normally be 8s but should be capped at 4s.
	if got := p.calculateExponentialBackoffDelay(cfg, 3); got != 4*time.Second {
		t.Fatalf("attempt 3 (capped): got %v want 4s", got)
	}
}

func TestWriteDebugLogMessage_RespectsFlag(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	p := &Provider{OperationLogger: captureLogger(&buf), EnableDebugLogging: false}

	p.writeDebugLogMessage("OP", "should not appear")
	if lines := logLines(&buf); len(lines) != 0 {
		t.Fatalf("expected no DEBUG output when flag is off, got %v", lines)
	}

	p.EnableDebugLogging = true
	p.writeDebugLogMessage("OP", "should appear")
	lines := logLines(&buf)
	if len(lines) != 1 {
		t.Fatalf("expected one DEBUG line, got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "[DEBUG]") {
		t.Fatalf("DEBUG line missing [DEBUG] tag: %q", lines[0])
	}
}

func TestWriteInfoAndError_AlwaysEmitWhenLoggerSet(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	p := &Provider{OperationLogger: captureLogger(&buf), EnableDebugLogging: false}

	p.writeInfoLogMessage("OP", "info")
	p.writeErrorLogMessage("OP", "err")

	lines := logLines(&buf)
	if len(lines) != 2 {
		t.Fatalf("expected INFO+ERROR lines regardless of debug flag, got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "[INFO]") || !strings.Contains(lines[1], "[ERROR]") {
		t.Fatalf("log levels not tagged correctly: %v", lines)
	}
}

func TestWriteLog_NoLoggerIsNoOp(t *testing.T) {
	t.Parallel()

	p := &Provider{EnableDebugLogging: true}
	// Should not panic with a nil logger.
	p.writeDebugLogMessage("OP", "msg")
	p.writeInfoLogMessage("OP", "msg")
	p.writeErrorLogMessage("OP", "msg")
}
