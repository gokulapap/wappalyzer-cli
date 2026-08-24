package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gokulapap/wappalyzer-cli/internal/scanner"
)

func TestWriteFormats(t *testing.T) {
	t.Parallel()
	results := []scanner.Result{{
		Input:      "example.com",
		URL:        "https://example.com",
		FinalURL:   "https://example.com/",
		StatusCode: 200,
		Title:      "Example",
		Technologies: []scanner.Technology{{
			Name:       "Nginx",
			Version:    "1.25",
			Confidence: 100,
			Categories: []string{"Web servers"},
		}},
		PagesScanned: 1,
		DurationMS:   12,
	}}

	t.Run("text", func(t *testing.T) {
		var output bytes.Buffer
		if err := Write(&output, results, Options{Format: "text"}); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		if !strings.Contains(output.String(), "Nginx 1.25") {
			t.Fatalf("text output = %q", output.String())
		}
	})

	t.Run("json", func(t *testing.T) {
		var output bytes.Buffer
		if err := Write(&output, results, Options{Format: "json"}); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		var document Document
		if err := json.Unmarshal(output.Bytes(), &document); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if document.SchemaVersion != SchemaVersion || document.Summary.Technologies != 1 {
			t.Fatalf("unexpected document: %#v", document)
		}
	})

	t.Run("jsonl", func(t *testing.T) {
		var output bytes.Buffer
		if err := Write(&output, results, Options{Format: "jsonl"}); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		if lines := strings.Count(strings.TrimSpace(output.String()), "\n") + 1; lines != 1 {
			t.Fatalf("JSONL lines = %d, want 1", lines)
		}
	})

	t.Run("csv", func(t *testing.T) {
		var output bytes.Buffer
		if err := Write(&output, results, Options{Format: "csv"}); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		records, err := csv.NewReader(strings.NewReader(output.String())).ReadAll()
		if err != nil {
			t.Fatalf("invalid CSV: %v", err)
		}
		if len(records) != 2 || records[1][5] != "Nginx" {
			t.Fatalf("unexpected CSV: %#v", records)
		}
	})
}

func TestBuildSummary(t *testing.T) {
	t.Parallel()
	summary := BuildSummary([]scanner.Result{
		{Technologies: []scanner.Technology{{Name: "A"}, {Name: "B"}}},
		{Error: "timeout", Technologies: []scanner.Technology{}},
	})
	if summary.Targets != 2 || summary.Succeeded != 1 || summary.Failed != 1 || summary.Technologies != 2 {
		t.Fatalf("summary = %#v", summary)
	}
}
