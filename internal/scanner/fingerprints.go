package scanner

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/andybalholm/cascadia"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"golang.org/x/net/html"
)

type detectionSignal struct {
	Name       string
	Version    string
	Confidence int
	Evidence   Evidence
}

type resource struct {
	URL  string
	Kind string
}

type documentAnalysis struct {
	Signals   []detectionSignal
	Links     []string
	Resources []resource
}

type technologyMetadata struct {
	Categories  []string
	Description string
	Website     string
	CPE         string
	Implies     []implication
}

type implication struct {
	Name       string
	Version    string
	Confidence int
}

type enhancedDetector struct {
	apps        []enhancedApp
	metadata    map[string]technologyMetadata
	headerRules map[string][]namedPattern
	cookieRules map[string][]namedPattern
	htmlRules   []namedPattern
	metaRules   map[string][]namedPattern
	jsRules     map[string][]namedPattern
	scriptRules []namedPattern
	srcRules    []namedPattern
	cssRules    []namedPattern
}

type enhancedApp struct {
	name     string
	domRules []domRule
}

type domRule struct {
	selectorText string
	selector     cascadia.Selector
	kind         string
	property     string
	pattern      *wappalyzer.ParsedPattern
}

type namedPattern struct {
	name    string
	pattern *wappalyzer.ParsedPattern
}

var safeJSPath = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)

var staticJSAssignment = regexp.MustCompile(`(?m)(?:globalThis\.|window\.)?([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*=\s*(?:"([^"\r\n]{0,1000})"|'([^'\r\n]{0,1000})'|` + "`([^`\\r\\n]{0,1000})`" + `|([+-]?(?:\d+(?:\.\d+)?|true|false|null)))`)

func newEnhancedDetector(fingerprints *wappalyzer.Fingerprints) *enhancedDetector {
	detector := &enhancedDetector{
		metadata:    make(map[string]technologyMetadata, len(fingerprints.Apps)),
		headerRules: make(map[string][]namedPattern),
		cookieRules: make(map[string][]namedPattern),
		metaRules:   make(map[string][]namedPattern),
		jsRules:     make(map[string][]namedPattern),
	}
	categories := wappalyzer.GetCategoriesMapping()

	appNames := make([]string, 0, len(fingerprints.Apps))
	for name := range fingerprints.Apps {
		appNames = append(appNames, name)
	}
	sort.Strings(appNames)

	for _, name := range appNames {
		fingerprint := fingerprints.Apps[name]
		categoryNames := make([]string, 0, len(fingerprint.Cats))
		for _, categoryID := range fingerprint.Cats {
			if category, ok := categories[categoryID]; ok {
				categoryNames = append(categoryNames, category.Name)
			}
		}
		sort.Strings(categoryNames)
		implies := make([]implication, 0, len(fingerprint.Implies))
		for _, raw := range fingerprint.Implies {
			implies = append(implies, parseImplication(raw))
		}
		detector.metadata[name] = technologyMetadata{
			Categories:  categoryNames,
			Description: fingerprint.Description,
			Website:     fingerprint.Website,
			CPE:         fingerprint.CPE,
			Implies:     implies,
		}

		app := enhancedApp{name: name}
		selectors := make([]string, 0, len(fingerprint.Dom))
		for selectorText := range fingerprint.Dom {
			selectors = append(selectors, selectorText)
		}
		sort.Strings(selectors)
		for _, selectorText := range selectors {
			selector, err := cascadia.Compile(strings.TrimSpace(selectorText))
			if err != nil {
				continue
			}
			properties := fingerprint.Dom[selectorText]
			app.domRules = append(app.domRules, compileDOMRules(selectorText, selector, properties)...)
		}
		if len(app.domRules) > 0 {
			detector.apps = append(detector.apps, app)
		}

		for header, rawPattern := range fingerprint.Headers {
			if pattern, err := wappalyzer.ParsePattern(rawPattern); err == nil {
				key := strings.ToLower(header)
				detector.headerRules[key] = append(detector.headerRules[key], namedPattern{name: name, pattern: pattern})
			}
		}
		for cookie, rawPattern := range fingerprint.Cookies {
			if pattern, err := wappalyzer.ParsePattern(rawPattern); err == nil {
				key := strings.ToLower(cookie)
				detector.cookieRules[key] = append(detector.cookieRules[key], namedPattern{name: name, pattern: pattern})
			}
		}
		for _, rawPattern := range fingerprint.HTML {
			if pattern, err := wappalyzer.ParsePattern(rawPattern); err == nil {
				detector.htmlRules = append(detector.htmlRules, namedPattern{name: name, pattern: pattern})
			}
		}
		for metaName, rawPatterns := range fingerprint.Meta {
			key := strings.ToLower(metaName)
			for _, rawPattern := range rawPatterns {
				if pattern, err := wappalyzer.ParsePattern(rawPattern); err == nil {
					detector.metaRules[key] = append(detector.metaRules[key], namedPattern{name: name, pattern: pattern})
				}
			}
		}
		for _, rawPattern := range fingerprint.Script {
			if pattern, err := wappalyzer.ParsePattern(rawPattern); err == nil {
				detector.scriptRules = append(detector.scriptRules, namedPattern{name: name, pattern: pattern})
			}
		}
		for _, rawPattern := range fingerprint.ScriptSrc {
			if pattern, err := wappalyzer.ParsePattern(rawPattern); err == nil {
				detector.srcRules = append(detector.srcRules, namedPattern{name: name, pattern: pattern})
			}
		}
		for _, rawPattern := range fingerprint.CSS {
			if pattern, err := wappalyzer.ParsePattern(rawPattern); err == nil {
				detector.cssRules = append(detector.cssRules, namedPattern{name: name, pattern: pattern})
			}
		}
		for path, rawPattern := range fingerprint.JS {
			if !safeJSPath.MatchString(path) {
				continue
			}
			if pattern, err := wappalyzer.ParsePattern(rawPattern); err == nil {
				detector.jsRules[path] = append(detector.jsRules[path], namedPattern{name: name, pattern: pattern})
			}
		}
	}

	return detector
}

func (d *enhancedDetector) AnalyzeResponse(headers http.Header, body []byte, pageURL string) []detectionSignal {
	var signals []detectionSignal
	headerNames := make([]string, 0, len(d.headerRules))
	for header := range d.headerRules {
		headerNames = append(headerNames, header)
	}
	sort.Strings(headerNames)
	for _, header := range headerNames {
		rules := d.headerRules[header]
		if values := headers.Values(header); len(values) > 0 {
			signals = append(signals, matchNamedPatterns(rules, strings.Join(values, ", "), "header", pageURL, header)...)
		}
	}

	for _, rawCookie := range headers.Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(rawCookie)
		if err != nil {
			continue
		}
		if rules := d.cookieRules[strings.ToLower(cookie.Name)]; len(rules) > 0 {
			signals = append(signals, matchNamedPatterns(rules, cookie.Value, "cookie", pageURL, cookie.Name)...)
		}
	}

	if looksLikeHTML(headers.Get("Content-Type"), body) {
		signals = append(signals, matchNamedPatterns(d.htmlRules, string(body), "html", pageURL, "HTML source")...)
	}
	return signals
}

func compileDOMRules(selectorText string, selector cascadia.Selector, properties map[string]interface{}) []domRule {
	var rules []domRule
	kinds := make([]string, 0, len(properties))
	for kind := range properties {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		rawValue := properties[kind]
		switch kind {
		case "exists", "text", "src":
			if value, ok := rawValue.(string); ok {
				if pattern, err := wappalyzer.ParsePattern(value); err == nil {
					property := ""
					if kind == "src" {
						property = "src"
					}
					rules = append(rules, domRule{selectorText: selectorText, selector: selector, kind: kind, property: property, pattern: pattern})
				}
			}
		case "attributes", "properties":
			values, ok := rawValue.(map[string]interface{})
			if !ok {
				continue
			}
			keys := make([]string, 0, len(values))
			for key := range values {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				value, ok := values[key].(string)
				if !ok {
					continue
				}
				if pattern, err := wappalyzer.ParsePattern(value); err == nil {
					rules = append(rules, domRule{selectorText: selectorText, selector: selector, kind: kind, property: key, pattern: pattern})
				}
			}
		}
	}
	return rules
}

func (d *enhancedDetector) AnalyzeDocument(body []byte, pageURL string) (documentAnalysis, error) {
	document, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return documentAnalysis{}, fmt.Errorf("parse HTML: %w", err)
	}
	analysis := documentAnalysis{}

	for _, app := range d.apps {
		for _, rule := range app.domRules {
			nodes := rule.selector.MatchAll(document)
			for _, node := range nodes {
				value, exists := domValue(node, rule)
				if !exists {
					continue
				}
				matched, version := evaluatePattern(rule.pattern, value)
				if !matched {
					continue
				}
				evidenceValue := rule.selectorText
				if rule.kind != "exists" {
					evidenceValue += " [" + rule.kind
					if rule.property != "" {
						evidenceValue += ":" + rule.property
					}
					evidenceValue += "]"
				}
				analysis.Signals = append(analysis.Signals, detectionSignal{
					Name:       app.name,
					Version:    version,
					Confidence: normalizedConfidence(rule.pattern.Confidence),
					Evidence:   Evidence{Type: "dom", Value: evidenceValue, URL: pageURL},
				})
				break
			}
		}
	}

	baseURL, _ := url.Parse(pageURL)
	if discoveredBase := findBaseURL(document, baseURL); discoveredBase != nil {
		baseURL = discoveredBase
	}
	analysis.Links, analysis.Resources = extractDocumentURLs(document, baseURL)
	analysis.Signals = append(analysis.Signals, d.analyzeMetaAndScriptSources(document, pageURL)...)

	for _, content := range elementContents(document, "script") {
		analysis.Signals = append(analysis.Signals, matchNamedPatterns(d.scriptRules, content, "script-source", pageURL, "inline script")...)
		analysis.Signals = append(analysis.Signals, d.analyzeStaticJS(content, pageURL, "inline-javascript")...)
	}
	for _, content := range elementContents(document, "style") {
		analysis.Signals = append(analysis.Signals, matchNamedPatterns(d.cssRules, content, "inline-style", pageURL, "inline style")...)
	}
	return analysis, nil
}

func (d *enhancedDetector) analyzeMetaAndScriptSources(document *html.Node, pageURL string) []detectionSignal {
	var signals []detectionSignal
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch strings.ToLower(node.Data) {
			case "meta":
				name, ok := nodeAttribute(node, "name")
				if !ok {
					name, ok = nodeAttribute(node, "property")
				}
				content, hasContent := nodeAttribute(node, "content")
				if ok && hasContent {
					if rules := d.metaRules[strings.ToLower(name)]; len(rules) > 0 {
						signals = append(signals, matchNamedPatterns(rules, content, "meta", pageURL, name)...)
					}
				}
			case "script":
				if source, ok := nodeAttribute(node, "src"); ok {
					signals = append(signals, matchNamedPatterns(d.srcRules, source, "script-src", pageURL, source)...)
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	return signals
}

func (d *enhancedDetector) AnalyzeAsset(body []byte, kind, assetURL string) []detectionSignal {
	if kind == "style" {
		return matchNamedPatterns(d.cssRules, string(body), "stylesheet", assetURL, assetURL)
	}
	signals := matchNamedPatterns(d.scriptRules, string(body), "script-source", assetURL, assetURL)
	return append(signals, d.analyzeStaticJS(string(body), assetURL, "javascript-asset")...)
}

func (d *enhancedDetector) Metadata(name string) technologyMetadata {
	return d.metadata[name]
}

func (d *enhancedDetector) analyzeStaticJS(source, sourceURL, evidenceType string) []detectionSignal {
	var signals []detectionSignal
	for _, match := range staticJSAssignment.FindAllStringSubmatch(source, -1) {
		path := match[1]
		rules, known := d.jsRules[path]
		if !known {
			continue
		}
		value := ""
		for _, candidate := range match[2:] {
			if candidate != "" {
				value = candidate
				break
			}
		}
		for _, rule := range rules {
			matched, version := evaluatePattern(rule.pattern, value)
			if !matched {
				continue
			}
			signals = append(signals, detectionSignal{
				Name:       rule.name,
				Version:    version,
				Confidence: normalizedConfidence(rule.pattern.Confidence),
				Evidence:   Evidence{Type: evidenceType, Value: path, URL: sourceURL},
			})
		}
	}
	return signals
}

func matchNamedPatterns(rules []namedPattern, content, evidenceType, sourceURL, evidenceValue string) []detectionSignal {
	best := make(map[string]detectionSignal)
	for _, rule := range rules {
		matched, version := evaluatePattern(rule.pattern, content)
		if !matched {
			continue
		}
		signal := detectionSignal{
			Name:       rule.name,
			Version:    version,
			Confidence: normalizedConfidence(rule.pattern.Confidence),
			Evidence:   Evidence{Type: evidenceType, Value: evidenceValue, URL: sourceURL},
		}
		current, exists := best[rule.name]
		if !exists || signal.Confidence > current.Confidence {
			best[rule.name] = signal
		} else if moreSpecificVersion(signal.Version, current.Version) {
			current.Version = signal.Version
			best[rule.name] = current
		}
	}
	names := make([]string, 0, len(best))
	for name := range best {
		names = append(names, name)
	}
	sort.Strings(names)
	signals := make([]detectionSignal, 0, len(names))
	for _, name := range names {
		signals = append(signals, best[name])
	}
	return signals
}

func evaluatePattern(pattern *wappalyzer.ParsedPattern, value string) (bool, string) {
	if pattern.SkipRegex {
		return true, strings.TrimSpace(pattern.Version)
	}
	return pattern.Evaluate(value)
}

func normalizedConfidence(confidence int) int {
	if confidence < 1 {
		return 1
	}
	if confidence > 100 {
		return 100
	}
	return confidence
}

func domValue(node *html.Node, rule domRule) (string, bool) {
	switch rule.kind {
	case "exists":
		return "", true
	case "text":
		return nodeText(node), true
	case "src", "attributes":
		return nodeAttribute(node, rule.property)
	case "properties":
		switch strings.ToLower(rule.property) {
		case "innertext", "textcontent":
			return nodeText(node), true
		case "innerhtml":
			var output bytes.Buffer
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				_ = html.Render(&output, child)
			}
			return output.String(), true
		case "classname":
			return nodeAttribute(node, "class")
		default:
			return nodeAttribute(node, rule.property)
		}
	default:
		return "", false
	}
}

func nodeAttribute(node *html.Node, name string) (string, bool) {
	for _, attribute := range node.Attr {
		if strings.EqualFold(attribute.Key, name) {
			return attribute.Val, true
		}
	}
	return "", false
}

func nodeText(node *html.Node) string {
	var builder strings.Builder
	var walk func(*html.Node)
	walk = func(current *html.Node) {
		if current.Type == html.TextNode {
			builder.WriteString(current.Data)
			builder.WriteByte(' ')
		}
		for child := current.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return strings.Join(strings.Fields(builder.String()), " ")
}

func elementContents(document *html.Node, elementName string) []string {
	var contents []string
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && strings.EqualFold(node.Data, elementName) {
			if _, hasSource := nodeAttribute(node, "src"); !hasSource {
				contents = append(contents, rawNodeText(node))
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	return contents
}

func rawNodeText(node *html.Node) string {
	var builder strings.Builder
	var walk func(*html.Node)
	walk = func(current *html.Node) {
		if current.Type == html.TextNode {
			builder.WriteString(current.Data)
		}
		for child := current.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return builder.String()
}

func findBaseURL(document *html.Node, fallback *url.URL) *url.URL {
	var found *url.URL
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if found != nil {
			return
		}
		if node.Type == html.ElementNode && strings.EqualFold(node.Data, "base") {
			if href, ok := nodeAttribute(node, "href"); ok {
				found = resolveWebURL(fallback, href)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	return found
}

func extractDocumentURLs(document *html.Node, baseURL *url.URL) ([]string, []resource) {
	var links []string
	var resources []resource
	seenLinks := make(map[string]struct{})
	seenResources := make(map[string]struct{})
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch strings.ToLower(node.Data) {
			case "a":
				if href, ok := nodeAttribute(node, "href"); ok {
					if resolved := resolveWebURL(baseURL, href); resolved != nil {
						value := resolved.String()
						if _, exists := seenLinks[value]; !exists {
							seenLinks[value] = struct{}{}
							links = append(links, value)
						}
					}
				}
			case "script":
				if source, ok := nodeAttribute(node, "src"); ok {
					appendResource(&resources, seenResources, baseURL, source, "script")
				}
			case "link":
				rel, _ := nodeAttribute(node, "rel")
				if strings.Contains(strings.ToLower(rel), "stylesheet") {
					if href, ok := nodeAttribute(node, "href"); ok {
						appendResource(&resources, seenResources, baseURL, href, "style")
					}
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	return links, resources
}

func appendResource(resources *[]resource, seen map[string]struct{}, baseURL *url.URL, reference, kind string) {
	resolved := resolveWebURL(baseURL, reference)
	if resolved == nil {
		return
	}
	key := kind + "\x00" + resolved.String()
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	*resources = append(*resources, resource{URL: resolved.String(), Kind: kind})
}

func resolveWebURL(baseURL *url.URL, reference string) *url.URL {
	reference = strings.TrimSpace(reference)
	if reference == "" || baseURL == nil {
		return nil
	}
	parsed, err := url.Parse(reference)
	if err != nil || parsed.User != nil {
		return nil
	}
	resolved := baseURL.ResolveReference(parsed)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return nil
	}
	if resolved.Hostname() == "" {
		return nil
	}
	resolved.Fragment = ""
	return resolved
}

func parseImplication(value string) implication {
	parts := strings.Split(value, `\;`)
	result := implication{Name: parts[0], Confidence: 100}
	for _, part := range parts[1:] {
		key, fieldValue, found := strings.Cut(part, ":")
		if !found {
			continue
		}
		switch key {
		case "confidence":
			var parsed int
			if _, err := fmt.Sscanf(fieldValue, "%d", &parsed); err == nil {
				result.Confidence = normalizedConfidence(parsed)
			}
		case "version":
			result.Version = fieldValue
		}
	}
	return result
}
