package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/gokulapap/wappalyzer-cli/internal/buildinfo"
	"github.com/gokulapap/wappalyzer-cli/internal/scanner"
)

const SchemaVersion = "1"

type Options struct {
	Format string
	Quiet  bool
	Color  bool
}

type Summary struct {
	Targets      int `json:"targets"`
	Succeeded    int `json:"succeeded"`
	Failed       int `json:"failed"`
	Technologies int `json:"technologies"`
}

type Document struct {
	SchemaVersion string           `json:"schema_version"`
	GeneratedAt   time.Time        `json:"generated_at"`
	Generator     buildinfo.Info   `json:"generator"`
	Summary       Summary          `json:"summary"`
	Results       []scanner.Result `json:"results"`
}

func Write(writer io.Writer, results []scanner.Result, options Options) error {
	switch options.Format {
	case "text":
		return writeText(writer, results, options)
	case "json":
		return writeJSON(writer, results)
	case "jsonl":
		return writeJSONLines(writer, results)
	case "csv":
		return writeCSV(writer, results)
	default:
		return fmt.Errorf("unsupported output format %q", options.Format)
	}
}

func BuildSummary(results []scanner.Result) Summary {
	summary := Summary{Targets: len(results)}
	for _, result := range results {
		if result.Error == "" {
			summary.Succeeded++
		} else {
			summary.Failed++
		}
		summary.Technologies += len(result.Technologies)
	}
	return summary
}

func writeText(writer io.Writer, results []scanner.Result, options Options) error {
	for index, result := range results {
		if options.Quiet {
			if result.Error != "" {
				if _, err := fmt.Fprintf(writer, "%s\tERROR\t%s\n", result.Input, result.Error); err != nil {
					return err
				}
				continue
			}
			for _, technology := range result.Technologies {
				if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\n", result.FinalURL, technology.Name, technology.Version); err != nil {
					return err
				}
			}
			continue
		}

		if index > 0 {
			if _, err := fmt.Fprintln(writer); err != nil {
				return err
			}
		}
		if result.Error != "" {
			if _, err := fmt.Fprintf(writer, "%s %s\n  %s\n", colorize(options.Color, red, "ERROR"), result.Input, result.Error); err != nil {
				return err
			}
			continue
		}

		header := fmt.Sprintf("%s  [%d]  %d technologies  %dms", result.FinalURL, result.StatusCode, len(result.Technologies), result.DurationMS)
		if _, err := fmt.Fprintln(writer, colorize(options.Color, cyan, header)); err != nil {
			return err
		}
		if result.Title != "" {
			if _, err := fmt.Fprintf(writer, "  %s %s\n", colorize(options.Color, dim, "title"), result.Title); err != nil {
				return err
			}
		}
		if result.Truncated {
			if _, err := fmt.Fprintf(writer, "  %s response limited to %d bytes\n", colorize(options.Color, yellow, "note"), result.BodyBytes); err != nil {
				return err
			}
		}
		for _, technology := range result.Technologies {
			name := technology.Name
			if technology.Version != "" {
				name += " " + technology.Version
			}
			categories := strings.Join(technology.Categories, ", ")
			if categories == "" {
				categories = "Uncategorized"
			}
			if _, err := fmt.Fprintf(writer, "  %-28s %s\n", colorize(options.Color, green, name), categories); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeJSON(writer io.Writer, results []scanner.Result) error {
	document := Document{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Generator:     buildinfo.Current(),
		Summary:       BuildSummary(results),
		Results:       results,
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func writeJSONLines(writer io.Writer, results []scanner.Result) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for _, result := range results {
		if err := encoder.Encode(result); err != nil {
			return err
		}
	}
	return nil
}

func writeCSV(writer io.Writer, results []scanner.Result) error {
	csvWriter := csv.NewWriter(writer)
	if err := csvWriter.Write([]string{
		"input", "url", "final_url", "status_code", "title", "technology", "version",
		"categories", "server", "content_type", "tls_version", "duration_ms", "error",
	}); err != nil {
		return err
	}

	for _, result := range results {
		technologies := result.Technologies
		if len(technologies) == 0 {
			technologies = []scanner.Technology{{}}
		}
		for _, technology := range technologies {
			if err := csvWriter.Write([]string{
				result.Input,
				result.URL,
				result.FinalURL,
				strconv.Itoa(result.StatusCode),
				result.Title,
				technology.Name,
				technology.Version,
				strings.Join(technology.Categories, ";"),
				result.Server,
				result.ContentType,
				result.TLSVersion,
				strconv.FormatInt(result.DurationMS, 10),
				result.Error,
			}); err != nil {
				return err
			}
		}
	}
	csvWriter.Flush()
	return csvWriter.Error()
}

const (
	reset  = "\x1b[0m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	cyan   = "\x1b[36m"
	dim    = "\x1b[2m"
)

func colorize(enabled bool, color, value string) string {
	if !enabled {
		return value
	}
	return color + value + reset
}
