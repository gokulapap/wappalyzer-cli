package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestScannerDetectsTechnologyAndMetadata(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.Header().Set("Server", "nginx/1.25.4")
		_, _ = fmt.Fprint(writer, `<!doctype html><title> Test   Site </title><script src="/wp-includes/js/wp-emoji.js"></script>`)
	}))
	defer server.Close()

	engine, err := New(testConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer engine.Close()

	results := engine.Scan(context.Background(), []Target{{Input: server.URL, Candidates: []string{server.URL}}})
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	result := results[0]
	if result.Error != "" {
		t.Fatalf("result error = %q", result.Error)
	}
	if result.StatusCode != http.StatusOK || result.Title != "Test Site" {
		t.Fatalf("unexpected metadata: status=%d title=%q", result.StatusCode, result.Title)
	}
	if !hasTechnology(result.Technologies, "Nginx") {
		t.Fatalf("technologies = %#v, expected Nginx", result.Technologies)
	}
}

func TestScannerRetriesTransientStatus(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Server", "nginx")
		_, _ = fmt.Fprint(writer, "<title>ready</title>")
	}))
	defer server.Close()

	config := testConfig()
	config.Retries = 1
	engine, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer engine.Close()

	results := engine.Scan(context.Background(), []Target{{Input: server.URL, Candidates: []string{server.URL}}})
	if results[0].StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; error=%q", results[0].StatusCode, results[0].Error)
	}
	if requests.Load() != 2 {
		t.Fatalf("requests = %d, want 2", requests.Load())
	}
}

func TestScannerLimitsBody(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(writer, strings.Repeat("x", 2048))
	}))
	defer server.Close()

	config := testConfig()
	config.MaxBodyBytes = 1024
	engine, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer engine.Close()

	result := engine.Scan(context.Background(), []Target{{Input: server.URL, Candidates: []string{server.URL}}})[0]
	if !result.Truncated || result.BodyBytes != 1024 {
		t.Fatalf("truncated=%v bodyBytes=%d, want true and 1024", result.Truncated, result.BodyBytes)
	}
}

func TestScannerUsesDetectorConcurrently(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Server", "nginx")
		_, _ = fmt.Fprint(writer, "<title>concurrent</title>")
	}))
	defer server.Close()

	config := testConfig()
	config.Concurrency = 8
	engine, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer engine.Close()

	targets := make([]Target, 32)
	for index := range targets {
		targets[index] = Target{Input: fmt.Sprintf("target-%d", index), Candidates: []string{server.URL}}
	}
	results := engine.Scan(context.Background(), targets)
	for index, result := range results {
		if result.Error != "" || !hasTechnology(result.Technologies, "Nginx") {
			t.Fatalf("result %d = %#v", index, result)
		}
	}
}

func TestSplitTechnologyVersionPreservesColonsInNames(t *testing.T) {
	t.Parallel()
	known := map[string]struct{}{"Nginx": {}, "RE:Guest": {}}
	tests := []struct {
		input       string
		wantedName  string
		wantedValue string
	}{
		{input: "Nginx:1.25.4", wantedName: "Nginx", wantedValue: "1.25.4"},
		{input: "RE:Guest", wantedName: "RE:Guest"},
		{input: "RE:Guest:2.0", wantedName: "RE:Guest", wantedValue: "2.0"},
		{input: "Unknown:Value", wantedName: "Unknown:Value"},
	}
	for _, test := range tests {
		name, version := splitTechnologyVersion(test.input, known)
		if name != test.wantedName || version != test.wantedValue {
			t.Fatalf("splitTechnologyVersion(%q) = (%q, %q), want (%q, %q)", test.input, name, version, test.wantedName, test.wantedValue)
		}
	}
}

func testConfig() Config {
	return Config{
		Concurrency:     2,
		Timeout:         3 * time.Second,
		Retries:         0,
		MaxBodyBytes:    1024 * 1024,
		MaxRedirects:    5,
		UserAgent:       DefaultUserAgent,
		FollowRedirects: true,
		Scheme:          "auto",
	}
}

func hasTechnology(technologies []Technology, name string) bool {
	for _, technology := range technologies {
		if technology.Name == name {
			return true
		}
	}
	return false
}
