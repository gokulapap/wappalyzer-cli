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

const SchemaVersion = "2"

type Options struct {
	Format  string
	Quiet   bool
	Color   bool
	Explain bool
}

type Summary struct {
	Targets      int `json:"targets"`
	Succeeded    int `json:"succeeded"`
	Failed       int `json:"failed"`
	Technologies int `json:"technologies"`
	Pages        int `json:"pages"`
	Assets       int `json:"assets"`
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
		summary.Pages += result.PagesScanned
		summary.Assets += result.AssetsScanned
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
		if result.PagesScanned > 1 || result.AssetsScanned > 0 {
			header += fmt.Sprintf("  pages:%d assets:%d", result.PagesScanned, result.AssetsScanned)
		}
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
		for _, partialError := range result.PartialErrors {
			if _, err := fmt.Fprintf(writer, "  %s %s\n", colorize(options.Color, yellow, "warning"), partialError); err != nil {
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
			if _, err := fmt.Fprintf(writer, "  %-28s %3d%%  %s\n", colorize(options.Color, green, name), technology.Confidence, categories); err != nil {
				return err
			}
			if options.Explain {
				for _, evidence := range technology.Evidence {
					detail := evidence.Value
					if detail == "" {
						detail = evidence.Type
					} else {
						detail = evidence.Type + ": " + detail
					}
					if evidence.URL != "" {
						detail += " (" + evidence.URL + ")"
					}
					if _, err := fmt.Fprintf(writer, "    - %s\n", detail); err != nil {
						return err
					}
				}
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
		"input", "url", "final_url", "status_code", "title", "technology", "version", "confidence",
		"categories", "evidence", "server", "content_type", "tls_version", "pages_scanned", "assets_scanned", "duration_ms", "error",
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
				strconv.Itoa(technology.Confidence),
				strings.Join(technology.Categories, ";"),
				formatEvidence(technology.Evidence),
				result.Server,
				result.ContentType,
				result.TLSVersion,
				strconv.Itoa(result.PagesScanned),
				strconv.Itoa(result.AssetsScanned),
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

func formatEvidence(evidence []scanner.Evidence) string {
	values := make([]string, 0, len(evidence))
	for _, item := range evidence {
		value := item.Type
		if item.Value != "" {
			value += ":" + item.Value
		}
		if item.URL != "" {
			value += "@" + item.URL
		}
		values = append(values, value)
	}
	return strings.Join(values, " | ")
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
