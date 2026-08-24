package scanner

import (
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		input      string
		scheme     string
		candidates []string
		wantError  bool
	}{
		{
			name:       "hostname probes secure first",
			input:      "Example.COM/path#fragment",
			scheme:     "auto",
			candidates: []string{"https://example.com/path", "http://example.com/path"},
		},
		{
			name:       "explicit URL is preserved",
			input:      "http://Example.COM:8080/app?q=1",
			scheme:     "auto",
			candidates: []string{"http://example.com:8080/app?q=1"},
		},
		{
			name:       "IPv6 target",
			input:      "[2001:db8::1]:8443",
			scheme:     "https",
			candidates: []string{"https://[2001:db8::1]:8443"},
		},
		{name: "credentials rejected", input: "https://user:secret@example.com", scheme: "auto", wantError: true},
		{name: "unsupported scheme", input: "ftp://example.com", scheme: "auto", wantError: true},
		{name: "invalid port", input: "example.com:99999", scheme: "auto", wantError: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			target, err := ParseTarget(test.input, test.scheme)
			if test.wantError {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget() error = %v", err)
			}
			if strings.Join(target.Candidates, "|") != strings.Join(test.candidates, "|") {
				t.Fatalf("candidates = %#v, want %#v", target.Candidates, test.candidates)
			}
		})
	}
}

func TestLoadTargetsDeduplicatesAndIgnoresComments(t *testing.T) {
	t.Parallel()
	targets, err := LoadTargets(
		[]string{"example.com", "example.com"},
		[]string{"api.example.com"},
		nil,
		strings.NewReader("# inventory\nwww.example.com\n\n"),
		true,
		"auto",
	)
	if err != nil {
		t.Fatalf("LoadTargets() error = %v", err)
	}
	if len(targets) != 3 {
		t.Fatalf("len(targets) = %d, want 3", len(targets))
	}
}
