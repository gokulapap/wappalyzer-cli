package scanner

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func LoadTargets(args, direct, files []string, stdin io.Reader, readStdin bool, scheme string) ([]Target, error) {
	inputs := make([]string, 0, len(args)+len(direct))
	inputs = append(inputs, args...)
	inputs = append(inputs, direct...)

	for _, path := range files {
		var reader io.Reader
		var closeFile func() error
		if path == "-" {
			reader = stdin
		} else {
			file, err := os.Open(path)
			if err != nil {
				return nil, fmt.Errorf("open target file %q: %w", path, err)
			}
			reader = file
			closeFile = file.Close
		}

		lines, err := readTargetLines(reader)
		if closeFile != nil {
			closeErr := closeFile()
			if err == nil {
				err = closeErr
			}
		}
		if err != nil {
			return nil, fmt.Errorf("read target file %q: %w", path, err)
		}
		inputs = append(inputs, lines...)
	}

	if readStdin && !contains(files, "-") {
		lines, err := readTargetLines(stdin)
		if err != nil {
			return nil, fmt.Errorf("read targets from stdin: %w", err)
		}
		inputs = append(inputs, lines...)
	}

	targets := make([]Target, 0, len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" || strings.HasPrefix(input, "#") {
			continue
		}
		target, err := ParseTarget(input, scheme)
		if err != nil {
			return nil, err
		}
		key := strings.Join(target.Candidates, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets supplied")
	}
	return targets, nil
}

func ParseTarget(input, scheme string) (Target, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return Target{}, fmt.Errorf("target is empty")
	}

	hasScheme := strings.Contains(input, "://")
	parseValue := input
	if !hasScheme {
		parseValue = "//" + input
	}
	u, err := url.Parse(parseValue)
	if err != nil {
		return Target{}, fmt.Errorf("invalid target %q: %w", input, err)
	}
	if u.User != nil {
		return Target{}, fmt.Errorf("invalid target %q: URL credentials are not supported; use --header", input)
	}
	if u.Hostname() == "" {
		return Target{}, fmt.Errorf("invalid target %q: hostname is required", input)
	}
	if _, err := parsePort(u); err != nil {
		return Target{}, fmt.Errorf("invalid target %q: %w", input, err)
	}
	u.Fragment = ""
	u.Host = normalizeHost(u)

	if hasScheme {
		u.Scheme = strings.ToLower(u.Scheme)
		if u.Scheme != "http" && u.Scheme != "https" {
			return Target{}, fmt.Errorf("invalid target %q: only http and https are supported", input)
		}
		return Target{Input: input, Candidates: []string{u.String()}}, nil
	}

	var schemes []string
	switch scheme {
	case "auto":
		schemes = []string{"https", "http"}
	case "https", "http":
		schemes = []string{scheme}
	default:
		return Target{}, fmt.Errorf("invalid scheme %q: expected auto, https, or http", scheme)
	}
	candidates := make([]string, 0, len(schemes))
	for _, candidateScheme := range schemes {
		candidate := *u
		candidate.Scheme = candidateScheme
		candidates = append(candidates, candidate.String())
	}
	return Target{Input: input, Candidates: candidates}, nil
}

func readTargetLines(reader io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func normalizeHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		host = net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	return host
}

func parsePort(u *url.URL) (string, error) {
	port := u.Port()
	if port == "" {
		return "", nil
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid port")
	}
	return port, nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
