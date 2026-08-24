package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	nginx := technologyByName(result.Technologies, "Nginx")
	if len(nginx.Evidence) == 0 || nginx.Evidence[0].Type != "header" || nginx.Evidence[0].Value != "server" {
		t.Fatalf("Nginx evidence = %#v, expected the Server header", nginx.Evidence)
	}
}

func TestScannerPreservesRuleConfidenceAndEvidence(t *testing.T) {
	t.Parallel()
	fingerprintPath := filepath.Join(t.TempDir(), "fingerprints.json")
	fingerprints := `{
  "apps": {
    "Evidence Tech": {
      "cats": [1],
      "headers": {"x-evidence": "^header$\\;confidence:30"},
      "cookies": {"evidence_cookie": "^cookie$\\;confidence:30"},
      "meta": {"generator": ["^Evidence$\\;confidence:40"]},
      "description": "Test technology",
      "website": "https://example.com"
    }
  }
}`
	if err := os.WriteFile(fingerprintPath, []byte(fingerprints), 0o600); err != nil {
		t.Fatalf("write fingerprints: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		writer.Header().Set("X-Evidence", "header")
		http.SetCookie(writer, &http.Cookie{Name: "evidence_cookie", Value: "cookie"})
		_, _ = fmt.Fprint(writer, `<meta name="generator" content="Evidence">`)
	}))
	defer server.Close()

	config := testConfig()
	config.FingerprintFile = fingerprintPath
	engine, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer engine.Close()

	result := engine.Scan(context.Background(), []Target{{Input: server.URL, Candidates: []string{server.URL}}})[0]
	technology := technologyByName(result.Technologies, "Evidence Tech")
	if technology == nil {
		t.Fatalf("technologies = %#v, expected Evidence Tech", result.Technologies)
	}
	if technology.Confidence != 100 || len(technology.Evidence) != 3 {
		t.Fatalf("technology = %#v, expected combined 100%% confidence and three evidence items", technology)
	}
	for _, evidenceType := range []string{"cookie", "header", "meta"} {
		if !hasEvidenceType(technology.Evidence, evidenceType) {
			t.Fatalf("evidence = %#v, expected %s", technology.Evidence, evidenceType)
		}
	}
}

func TestScannerEvaluatesCoreFingerprintTypes(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		writer.Header().Set("Server", "now")
		http.SetCookie(writer, &http.Cookie{Name: "_uetsid", Value: "ABCDEF"})
		_, _ = fmt.Fprint(writer, `<meta name="generator" content="mura cms 1"><script src="/1.2/aframe.min.js"></script>`)
	}))
	defer server.Close()

	engine, err := New(testConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer engine.Close()

	result := engine.Scan(context.Background(), []Target{{Input: server.URL, Candidates: []string{server.URL}}})[0]
	checks := []struct {
		name         string
		version      string
		evidenceType string
	}{
		{name: "Vercel", evidenceType: "header"},
		{name: "Microsoft Advertising", evidenceType: "cookie"},
		{name: "Mura CMS", version: "1", evidenceType: "meta"},
		{name: "A-Frame", version: "1.2", evidenceType: "script-src"},
	}
	for _, check := range checks {
		technology := technologyByName(result.Technologies, check.name)
		if technology == nil {
			t.Fatalf("technologies = %#v, expected %s", result.Technologies, check.name)
		}
		if check.version != "" && technology.Version != check.version {
			t.Fatalf("%s version = %q, want %q", check.name, technology.Version, check.version)
		}
		if !hasEvidenceType(technology.Evidence, check.evidenceType) {
			t.Fatalf("%s evidence = %#v, expected %s", check.name, technology.Evidence, check.evidenceType)
		}
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

func TestScannerDetectsDOMFingerprints(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(writer, `<!doctype html><model-viewer src="demo.glb"></model-viewer>`)
	}))
	defer server.Close()

	engine, err := New(testConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer engine.Close()

	result := engine.Scan(context.Background(), []Target{{Input: server.URL, Candidates: []string{server.URL}}})[0]
	technology := technologyByName(result.Technologies, "<model-viewer>")
	if technology == nil {
		t.Fatalf("technologies = %#v, expected <model-viewer>", result.Technologies)
	}
	if technology.Confidence != 100 || len(technology.Evidence) == 0 || technology.Evidence[0].Type != "dom" {
		t.Fatalf("technology = %#v, expected DOM evidence at 100%% confidence", technology)
	}
}

func TestScannerDetectsInlineScriptSourceAndStaticJavaScript(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(writer, `<script>6valley_cookie_consent(); window.AFRAME.version = "1.5.0";</script>`)
	}))
	defer server.Close()

	engine, err := New(testConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer engine.Close()

	result := engine.Scan(context.Background(), []Target{{Input: server.URL, Candidates: []string{server.URL}}})[0]
	if !hasTechnology(result.Technologies, "6Valley eCommerce CMS") {
		t.Fatalf("technologies = %#v, expected inline script-source detection", result.Technologies)
	}
	aFrame := technologyByName(result.Technologies, "A-Frame")
	if aFrame == nil || aFrame.Version != "1.5.0" {
		t.Fatalf("A-Frame = %#v, expected statically assigned version 1.5.0", aFrame)
	}
	if !hasTechnology(result.Technologies, "Three.js") {
		t.Fatalf("technologies = %#v, expected implied Three.js", result.Technologies)
	}
}

func TestScannerCrawlsSafeSameHostPages(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		if request.URL.Path == "/details" {
			_, _ = fmt.Fprint(writer, `<model-viewer></model-viewer>`)
			return
		}
		_, _ = fmt.Fprint(writer, `<a href="/details">Details</a><a href="/logout">Log out</a>`)
	}))
	defer server.Close()

	config := testConfig()
	config.CrawlPages = 2
	engine, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer engine.Close()

	result := engine.Scan(context.Background(), []Target{{Input: server.URL, Candidates: []string{server.URL}}})[0]
	if result.PagesScanned != 2 || !hasTechnology(result.Technologies, "<model-viewer>") {
		t.Fatalf("result = %#v, expected two pages and DOM technology", result)
	}
}

func TestScannerInspectsLinkedStylesheets(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/app.css" {
			writer.Header().Set("Content-Type", "text/css")
			_, _ = fmt.Fprint(writer, `.ClickOnceInfoText { display: block; }`)
			return
		}
		writer.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(writer, `<link rel="stylesheet" href="/app.css">`)
	}))
	defer server.Close()

	config := testConfig()
	config.FetchAssets = true
	engine, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer engine.Close()

	result := engine.Scan(context.Background(), []Target{{Input: server.URL, Candidates: []string{server.URL}}})[0]
	if result.AssetsScanned != 1 || !hasTechnology(result.Technologies, "ClickOnce") {
		t.Fatalf("result = %#v, expected one asset and ClickOnce", result)
	}
}

func TestScannerKeepsPartialAssetFailuresNonFatal(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/missing.js" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(writer, `<script src="/missing.js"></script><model-viewer></model-viewer>`)
	}))
	defer server.Close()

	config := testConfig()
	config.FetchAssets = true
	engine, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer engine.Close()

	result := engine.Scan(context.Background(), []Target{{Input: server.URL, Candidates: []string{server.URL}}})[0]
	if result.Error != "" || len(result.PartialErrors) != 1 || !hasTechnology(result.Technologies, "<model-viewer>") {
		t.Fatalf("result = %#v, expected a successful result with one partial error", result)
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
		CrawlPages:      1,
		MaxAssets:       20,
		AssetScope:      "same-origin",
		MinConfidence:   1,
	}
}

func hasTechnology(technologies []Technology, name string) bool {
	return technologyByName(technologies, name) != nil
}

func technologyByName(technologies []Technology, name string) *Technology {
	for _, technology := range technologies {
		if technology.Name == name {
			return &technology
		}
	}
	return nil
}

func hasEvidenceType(evidence []Evidence, evidenceType string) bool {
	for _, item := range evidence {
		if item.Type == evidenceType {
			return true
		}
	}
	return false
}
