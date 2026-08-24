package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gokulapap/wappalyzer-cli/internal/buildinfo"
	"github.com/gokulapap/wappalyzer-cli/internal/report"
	"github.com/gokulapap/wappalyzer-cli/internal/scanner"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/spf13/cobra"
	"golang.org/x/net/http/httpguts"
)

type options struct {
	URLs            []string
	Files           []string
	Output          string
	LegacyOutput    string
	Format          string
	Concurrency     int
	Timeout         time.Duration
	Retries         int
	MaxBody         string
	MaxRedirects    int
	Rate            float64
	UserAgent       string
	Headers         []string
	Proxy           string
	Insecure        bool
	FollowRedirects bool
	Scheme          string
	FingerprintFile string
	Categories      []string
	ReadStdin       bool
	Quiet           bool
	Color           string
	FailOnError     bool
}

type streams struct {
	in     io.Reader
	out    io.Writer
	errOut io.Writer
}

type targetFailuresError struct {
	count int
}

func (e targetFailuresError) Error() string {
	return fmt.Sprintf("%d target(s) failed", e.count)
}

func Execute(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) int {
	root := newRootCommand(streams{in: in, out: out, errOut: errOut})
	root.SetArgs(rewriteLegacyArgs(args))
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		_, _ = fmt.Fprintln(errOut, "error: interrupted")
		return 130
	}
	var targetFailures targetFailuresError
	if errors.As(err, &targetFailures) {
		return 1
	}
	_, _ = fmt.Fprintf(errOut, "error: %v\n", err)
	return 2
}

func newRootCommand(ioStreams streams) *cobra.Command {
	var opts options
	root := &cobra.Command{
		Use:   "wappy [flags] [target ...]",
		Short: "Fast web technology fingerprinting",
		Long: "wappy fingerprints web technologies from HTTP response headers, cookies, and HTML.\n" +
			"Targets may be URLs, hostnames, positional arguments, files, or stdin.",
		Example: strings.TrimSpace(`
  wappy example.com
  wappy -u https://app.example.com -u api.example.com
  wappy -f targets.txt --format jsonl -o results.jsonl
  subfinder -silent -d example.com | wappy --stdin -q`),
		Args:          cobra.ArbitraryArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		Version:       buildinfo.Version,
		RunE: func(command *cobra.Command, args []string) error {
			return runScan(command.Context(), command, args, opts, ioStreams)
		},
	}
	root.SetOut(ioStreams.out)
	root.SetErr(ioStreams.errOut)
	root.SetVersionTemplate("{{.Name}} {{.Version}}\n")

	flags := root.Flags()
	flags.StringArrayVarP(&opts.URLs, "url", "u", nil, "target URL or hostname (repeatable)")
	flags.StringArrayVarP(&opts.Files, "file", "f", nil, "target file, one per line; use - for stdin (repeatable)")
	flags.BoolVar(&opts.ReadStdin, "stdin", false, "read newline-delimited targets from stdin")
	flags.StringVarP(&opts.Output, "output", "o", "", "output file (written atomically; default stdout)")
	flags.StringVar(&opts.LegacyOutput, "writefile", "", "output file")
	_ = flags.MarkHidden("writefile")
	flags.StringVar(&opts.Format, "format", "text", "output format: text, json, jsonl, or csv")
	flags.BoolVarP(&opts.Quiet, "quiet", "q", false, "print URL, technology, and version as tab-separated text")
	flags.StringVar(&opts.Color, "color", "auto", "color mode for text: auto, always, or never")

	flags.IntVarP(&opts.Concurrency, "concurrency", "c", 10, "maximum concurrent targets")
	flags.DurationVar(&opts.Timeout, "timeout", 15*time.Second, "per-request timeout")
	flags.IntVar(&opts.Retries, "retries", 1, "retries for transient network and HTTP failures")
	flags.StringVar(&opts.MaxBody, "max-body", "5MiB", "maximum response body to inspect (for example 512KiB, 5MiB)")
	flags.Float64Var(&opts.Rate, "rate", 0, "global request rate per second; 0 is unlimited")
	flags.StringVar(&opts.Scheme, "scheme", "auto", "scheme for hostnames: auto, https, or http")

	flags.BoolVar(&opts.FollowRedirects, "follow-redirects", true, "follow HTTP redirects")
	flags.IntVar(&opts.MaxRedirects, "max-redirects", 10, "maximum redirects per target")
	flags.BoolVarP(&opts.Insecure, "insecure", "k", false, "skip TLS certificate verification")
	flags.StringVar(&opts.Proxy, "proxy", "", "HTTP, HTTPS, or SOCKS5 proxy URL")
	flags.StringVar(&opts.UserAgent, "user-agent", defaultUserAgent(), "HTTP User-Agent")
	flags.StringArrayVarP(&opts.Headers, "header", "H", nil, "HTTP header in 'Name: value' form (repeatable)")

	flags.StringVar(&opts.FingerprintFile, "fingerprints", "", "merge a custom Wappalyzer fingerprint JSON file")
	flags.StringArrayVar(&opts.Categories, "category", nil, "include technologies in this category (repeatable)")
	flags.BoolVar(&opts.FailOnError, "fail-on-error", true, "exit 1 if any target fails")

	root.AddCommand(newVersionCommand(ioStreams.out))
	root.AddCommand(newCategoriesCommand(ioStreams.out))
	return root
}

func runScan(ctx context.Context, command *cobra.Command, args []string, opts options, ioStreams streams) error {
	if opts.Output != "" && opts.LegacyOutput != "" && opts.Output != opts.LegacyOutput {
		return fmt.Errorf("--output and --writefile cannot specify different files")
	}
	if opts.Output == "" {
		opts.Output = opts.LegacyOutput
	}
	if !command.Flags().Changed("format") {
		opts.Format = inferFormat(opts.Output, opts.Format)
	}
	if err := validateOutputOptions(opts); err != nil {
		return err
	}

	maxBodyBytes, err := parseByteSize(opts.MaxBody)
	if err != nil {
		return fmt.Errorf("invalid --max-body: %w", err)
	}
	headers, err := parseHeaders(opts.Headers)
	if err != nil {
		return err
	}

	readStdin := opts.ReadStdin
	if len(args) == 0 && len(opts.URLs) == 0 && len(opts.Files) == 0 {
		readStdin = !isTerminalReader(ioStreams.in)
	}
	targets, err := scanner.LoadTargets(args, opts.URLs, opts.Files, ioStreams.in, readStdin, opts.Scheme)
	if err != nil {
		return err
	}

	engine, err := scanner.New(scanner.Config{
		Concurrency:     opts.Concurrency,
		Timeout:         opts.Timeout,
		Retries:         opts.Retries,
		MaxBodyBytes:    maxBodyBytes,
		MaxRedirects:    opts.MaxRedirects,
		RatePerSecond:   opts.Rate,
		UserAgent:       opts.UserAgent,
		Headers:         headers,
		ProxyURL:        opts.Proxy,
		InsecureTLS:     opts.Insecure,
		FollowRedirects: opts.FollowRedirects,
		Scheme:          opts.Scheme,
		FingerprintFile: opts.FingerprintFile,
		Categories:      opts.Categories,
	})
	if err != nil {
		return err
	}
	defer engine.Close()

	results := engine.Scan(ctx, targets)
	color := opts.Color == "always" || (opts.Color == "auto" && opts.Output == "" && isTerminalWriter(ioStreams.out))
	if err := writeResults(opts.Output, ioStreams.out, results, report.Options{
		Format: opts.Format,
		Quiet:  opts.Quiet,
		Color:  color,
	}); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	summary := report.BuildSummary(results)
	if opts.FailOnError && summary.Failed > 0 {
		return targetFailuresError{count: summary.Failed}
	}
	return nil
}

func newVersionCommand(writer io.Writer) *cobra.Command {
	var asJSON bool
	command := &cobra.Command{
		Use:   "version",
		Short: "Print build information",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			info := buildinfo.Current()
			if asJSON {
				encoder := json.NewEncoder(writer)
				encoder.SetIndent("", "  ")
				return encoder.Encode(info)
			}
			_, err := fmt.Fprintf(writer, "wappy %s (%s, %s, %s, built %s)\n", info.Version, info.Commit, info.GoVersion, info.Platform, info.BuiltAt)
			return err
		},
	}
	command.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return command
}

func newCategoriesCommand(writer io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "categories",
		Short: "List available technology categories",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			mapping := wappalyzer.GetCategoriesMapping()
			categories := make([]string, 0, len(mapping))
			for _, category := range mapping {
				categories = append(categories, category.Name)
			}
			sort.Strings(categories)
			for _, category := range categories {
				if _, err := fmt.Fprintln(writer, category); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func validateOutputOptions(opts options) error {
	switch opts.Format {
	case "text", "json", "jsonl", "csv":
	default:
		return fmt.Errorf("format must be text, json, jsonl, or csv")
	}
	if opts.Quiet && opts.Format != "text" {
		return fmt.Errorf("--quiet can only be used with text output")
	}
	switch opts.Color {
	case "auto", "always", "never":
	default:
		return fmt.Errorf("color must be auto, always, or never")
	}
	if opts.Output == "-" {
		opts.Output = ""
	}
	return nil
}

func parseHeaders(values []string) (http.Header, error) {
	headers := make(http.Header)
	for _, raw := range values {
		name, value, found := strings.Cut(raw, ":")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !found || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return nil, fmt.Errorf("invalid header %q: expected 'Name: value'", raw)
		}
		headers.Add(name, value)
	}
	return headers, nil
}

func parseByteSize(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("value is empty")
	}
	upper := strings.ToUpper(value)
	multipliers := []struct {
		suffix     string
		multiplier float64
	}{
		{"GIB", 1024 * 1024 * 1024}, {"GB", 1000 * 1000 * 1000},
		{"MIB", 1024 * 1024}, {"MB", 1000 * 1000},
		{"KIB", 1024}, {"KB", 1000}, {"B", 1},
	}
	multiplier := float64(1)
	number := upper
	for _, unit := range multipliers {
		if strings.HasSuffix(upper, unit.suffix) {
			multiplier = unit.multiplier
			number = strings.TrimSpace(strings.TrimSuffix(upper, unit.suffix))
			break
		}
	}
	numeric, err := strconv.ParseFloat(number, 64)
	if err != nil || numeric <= 0 {
		return 0, fmt.Errorf("expected a positive size such as 512KiB or 5MiB")
	}
	bytes := numeric * multiplier
	if math.IsNaN(bytes) || math.IsInf(bytes, 0) || bytes > float64(^uint64(0)>>1) {
		return 0, fmt.Errorf("size is too large")
	}
	return int64(bytes), nil
}

func inferFormat(path, fallback string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "json"
	case ".jsonl", ".ndjson":
		return "jsonl"
	case ".csv":
		return "csv"
	default:
		return fallback
	}
}

func writeResults(path string, stdout io.Writer, results []scanner.Result, options report.Options) error {
	if path == "" || path == "-" {
		return report.Write(stdout, results, options)
	}

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".wappy-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := report.Write(temporary, results, options); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func defaultUserAgent() string {
	return fmt.Sprintf("wappy/%s (+https://github.com/gokulapap/wappalyzer-cli)", buildinfo.Version)
}

func isTerminalReader(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func isTerminalWriter(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func rewriteLegacyArgs(args []string) []string {
	rewritten := append([]string(nil), args...)
	for index, arg := range rewritten {
		if arg == "-wf" {
			rewritten[index] = "--output"
		}
	}
	return rewritten
}
