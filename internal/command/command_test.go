package command

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseByteSize(t *testing.T) {
	t.Parallel()
	tests := map[string]int64{
		"1024":    1024,
		"1KiB":    1024,
		"1.5 MiB": 1572864,
		"2MB":     2000000,
	}
	for input, wanted := range tests {
		input, wanted := input, wanted
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			actual, err := parseByteSize(input)
			if err != nil {
				t.Fatalf("parseByteSize(%q) error = %v", input, err)
			}
			if actual != wanted {
				t.Fatalf("parseByteSize(%q) = %d, want %d", input, actual, wanted)
			}
		})
	}
	for _, input := range []string{"", "zero", "-1MiB", "0", "NaNMiB", "InfGiB"} {
		if _, err := parseByteSize(input); err == nil {
			t.Fatalf("parseByteSize(%q) expected error", input)
		}
	}
}

func TestExecuteJSONScan(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Wappy-Test") != "enabled" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "text/html")
		writer.Header().Set("Server", "nginx")
		_, _ = fmt.Fprint(writer, "<title>Command Test</title>")
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	exitCode := Execute(context.Background(), []string{
		server.URL,
		"--format", "json",
		"--header", "X-Wappy-Test: enabled",
		"--retries", "0",
	}, bytes.NewReader(nil), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr=%q", exitCode, stderr.String())
	}

	var output struct {
		Summary struct {
			Succeeded int `json:"succeeded"`
		} `json:"summary"`
		Results []struct {
			Title string `json:"title"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, stdout.String())
	}
	if output.Summary.Succeeded != 1 || len(output.Results) != 1 || output.Results[0].Title != "Command Test" {
		t.Fatalf("unexpected output: %#v", output)
	}
}

func TestExecuteRejectsInvalidOptions(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	exitCode := Execute(context.Background(), []string{"example.com", "--format", "yaml"}, bytes.NewReader(nil), &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if stderr.Len() == 0 {
		t.Fatal("expected an error message")
	}
}
