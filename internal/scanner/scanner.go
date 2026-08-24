package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"golang.org/x/net/html"
)

type Scanner struct {
	config   Config
	client   *http.Client
	enhanced *enhancedDetector
	limiter  *rateLimiter
}

func New(config Config) (*Scanner, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	var (
		detector *wappalyzer.Wappalyze
		err      error
	)
	if config.FingerprintFile == "" {
		detector, err = wappalyzer.New()
	} else {
		detector, err = wappalyzer.NewFromFile(config.FingerprintFile, true, true)
	}
	if err != nil {
		return nil, fmt.Errorf("load technology fingerprints: %w", err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = max(100, config.Concurrency*2)
	transport.MaxIdleConnsPerHost = max(10, config.Concurrency)
	transport.ResponseHeaderTimeout = config.Timeout
	transport.TLSHandshakeTimeout = min(config.Timeout, 10*time.Second)
	transport.DialContext = (&net.Dialer{
		Timeout:   min(config.Timeout, 10*time.Second),
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.TLSClientConfig = &tls.Config{ //nolint:gosec // Explicitly controlled by --insecure.
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: config.InsecureTLS,
	}
	if config.ProxyURL != "" {
		proxyURL, parseErr := url.Parse(config.ProxyURL)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", parseErr)
		}
		if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" && proxyURL.Scheme != "socks5" && proxyURL.Scheme != "socks5h" {
			return nil, fmt.Errorf("invalid proxy URL: unsupported scheme %q", proxyURL.Scheme)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{Transport: transport, Timeout: config.Timeout}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if !config.FollowRedirects {
			return http.ErrUseLastResponse
		}
		if request.URL.User != nil {
			return fmt.Errorf("redirect URL contains credentials")
		}
		if len(via) >= config.MaxRedirects {
			return fmt.Errorf("stopped after %d redirects", config.MaxRedirects)
		}
		return nil
	}

	return &Scanner{
		config:   config,
		client:   client,
		enhanced: newEnhancedDetector(detector.GetFingerprints()),
		limiter:  newRateLimiter(config.RatePerSecond),
	}, nil
}

func (s *Scanner) Close() {
	s.client.CloseIdleConnections()
}

func (s *Scanner) Scan(ctx context.Context, targets []Target) []Result {
	results := make([]Result, len(targets))
	jobs := make(chan int)
	var workers sync.WaitGroup

	workerCount := min(s.config.Concurrency, len(targets))
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for index := range jobs {
				results[index] = s.scanTarget(ctx, targets[index])
			}
		}()
	}

	for index := range targets {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			workers.Wait()
			markUnprocessed(results, targets, ctx.Err())
			return results
		}
	}
	close(jobs)
	workers.Wait()
	return results
}

func (s *Scanner) scanTarget(ctx context.Context, target Target) Result {
	started := time.Now()
	result := Result{Input: target.Input, Technologies: make([]Technology, 0)}
	errorsByCandidate := make([]string, 0, len(target.Candidates))

	for _, candidate := range target.Candidates {
		result.URL = candidate
		response, body, truncated, err := s.fetch(ctx, candidate)
		if err != nil {
			errorsByCandidate = append(errorsByCandidate, fmt.Sprintf("%s: %v", candidate, err))
			continue
		}

		result.FinalURL = response.Request.URL.String()
		result.StatusCode = response.StatusCode
		result.Server = response.Header.Get("Server")
		result.ContentType = response.Header.Get("Content-Type")
		result.BodyBytes = int64(len(body))
		result.Truncated = truncated
		if response.TLS != nil {
			result.TLSVersion = tlsVersionName(response.TLS.Version)
		}
		result.Title = findTitle(body)

		technologies := newTechnologySet(s.enhanced)
		firstURL := response.Request.URL.String()
		origin, _ := url.Parse(firstURL)
		visitedPages := map[string]struct{}{canonicalURL(firstURL): {}}
		queuedPages := make(map[string]struct{})
		var pageQueue []string
		var assets []resource
		seenAssets := make(map[string]struct{})

		inspectPage := func(pageURL string, headers http.Header, pageBody []byte) {
			result.PagesScanned++
			technologies.AddAll(s.enhanced.AnalyzeResponse(headers, pageBody, pageURL))
			if !looksLikeHTML(headers.Get("Content-Type"), pageBody) {
				return
			}
			analysis, analysisErr := s.enhanced.AnalyzeDocument(pageBody, pageURL)
			if analysisErr != nil {
				result.PartialErrors = append(result.PartialErrors, fmt.Sprintf("%s: %v", pageURL, analysisErr))
				return
			}
			technologies.AddAll(analysis.Signals)
			for _, link := range analysis.Links {
				if !sameHost(origin, link) || !safeCrawlURL(link) {
					continue
				}
				key := canonicalURL(link)
				if _, visited := visitedPages[key]; visited {
					continue
				}
				if _, queued := queuedPages[key]; queued {
					continue
				}
				queuedPages[key] = struct{}{}
				pageQueue = append(pageQueue, link)
			}
			for _, asset := range analysis.Resources {
				if s.config.AssetScope == "same-origin" && !sameHost(origin, asset.URL) {
					continue
				}
				key := asset.Kind + "\x00" + canonicalURL(asset.URL)
				if _, seen := seenAssets[key]; seen {
					continue
				}
				seenAssets[key] = struct{}{}
				assets = append(assets, asset)
			}
		}

		inspectPage(firstURL, response.Header, body)
		for result.PagesScanned < s.config.CrawlPages && len(pageQueue) > 0 && ctx.Err() == nil {
			pageURL := pageQueue[0]
			pageQueue = pageQueue[1:]
			delete(queuedPages, canonicalURL(pageURL))
			visitedPages[canonicalURL(pageURL)] = struct{}{}
			pageResponse, pageBody, _, pageErr := s.fetch(ctx, pageURL)
			if pageErr != nil {
				result.PartialErrors = append(result.PartialErrors, fmt.Sprintf("crawl %s: %v", pageURL, pageErr))
				continue
			}
			resolvedPageURL := pageResponse.Request.URL.String()
			if !sameHost(origin, resolvedPageURL) {
				result.PartialErrors = append(result.PartialErrors, fmt.Sprintf("crawl %s: redirected outside target host", pageURL))
				continue
			}
			inspectPage(resolvedPageURL, pageResponse.Header, pageBody)
		}

		if s.config.FetchAssets {
			for _, asset := range assets {
				if result.AssetsScanned >= s.config.MaxAssets || ctx.Err() != nil {
					break
				}
				assetResponse, assetBody, _, assetErr := s.fetch(ctx, asset.URL)
				if assetErr != nil {
					result.PartialErrors = append(result.PartialErrors, fmt.Sprintf("asset %s: %v", asset.URL, assetErr))
					continue
				}
				if assetResponse.StatusCode < 200 || assetResponse.StatusCode >= 300 {
					result.PartialErrors = append(result.PartialErrors, fmt.Sprintf("asset %s: HTTP %d", asset.URL, assetResponse.StatusCode))
					continue
				}
				result.AssetsScanned++
				technologies.AddAll(s.enhanced.AnalyzeAsset(assetBody, asset.Kind, assetResponse.Request.URL.String()))
			}
		}

		technologies.AddImplications()
		result.Technologies = technologies.Technologies(s.config.Categories, s.config.MinConfidence)
		result.DurationMS = time.Since(started).Milliseconds()
		return result
	}

	result.Error = strings.Join(errorsByCandidate, "; ")
	if result.Error == "" {
		result.Error = "request failed"
	}
	result.DurationMS = time.Since(started).Milliseconds()
	return result
}

func (s *Scanner) fetch(ctx context.Context, targetURL string) (*http.Response, []byte, bool, error) {
	for attempt := 0; attempt <= s.config.Retries; attempt++ {
		if err := s.limiter.Wait(ctx); err != nil {
			return nil, nil, false, err
		}

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			return nil, nil, false, err
		}
		request.Header.Set("User-Agent", s.config.UserAgent)
		request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		for name, values := range s.config.Headers {
			request.Header.Del(name)
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}

		response, err := s.client.Do(request)
		if err != nil {
			if attempt < s.config.Retries && retryableError(err) {
				if waitErr := waitForRetry(ctx, retryDelay(attempt, nil)); waitErr != nil {
					return nil, nil, false, waitErr
				}
				continue
			}
			return nil, nil, false, err
		}

		if attempt < s.config.Retries && retryableStatus(response.StatusCode) {
			delay := retryDelay(attempt, response)
			_, _ = io.CopyN(io.Discard, response.Body, 8*1024)
			_ = response.Body.Close()
			if err := waitForRetry(ctx, delay); err != nil {
				return nil, nil, false, err
			}
			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(response.Body, s.config.MaxBodyBytes+1))
		closeErr := response.Body.Close()
		if readErr != nil {
			return nil, nil, false, fmt.Errorf("read response: %w", readErr)
		}
		if closeErr != nil {
			return nil, nil, false, fmt.Errorf("close response: %w", closeErr)
		}
		truncated := int64(len(body)) > s.config.MaxBodyBytes
		if truncated {
			body = body[:s.config.MaxBodyBytes]
		}
		return response, body, truncated, nil
	}
	return nil, nil, false, errors.New("request failed after retries")
}

func validateConfig(config Config) error {
	if config.Concurrency < 1 || config.Concurrency > 1000 {
		return fmt.Errorf("concurrency must be between 1 and 1000")
	}
	if config.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than zero")
	}
	if config.Retries < 0 || config.Retries > 10 {
		return fmt.Errorf("retries must be between 0 and 10")
	}
	if config.MaxBodyBytes < 1024 || config.MaxBodyBytes > 100*1024*1024 {
		return fmt.Errorf("max body must be between 1 KiB and 100 MiB")
	}
	if config.MaxRedirects < 1 || config.MaxRedirects > 50 {
		return fmt.Errorf("max redirects must be between 1 and 50")
	}
	if config.RatePerSecond < 0 || config.RatePerSecond > 10000 {
		return fmt.Errorf("rate must be between 0 and 10000 requests per second")
	}
	if config.UserAgent == "" {
		return fmt.Errorf("user agent cannot be empty")
	}
	if config.Scheme != "auto" && config.Scheme != "https" && config.Scheme != "http" {
		return fmt.Errorf("scheme must be auto, https, or http")
	}
	if config.CrawlPages < 1 || config.CrawlPages > 50 {
		return fmt.Errorf("crawl pages must be between 1 and 50")
	}
	if config.MaxAssets < 0 || config.MaxAssets > 500 {
		return fmt.Errorf("max assets must be between 0 and 500")
	}
	if config.AssetScope != "same-origin" && config.AssetScope != "all" {
		return fmt.Errorf("asset scope must be same-origin or all")
	}
	if config.MinConfidence < 1 || config.MinConfidence > 100 {
		return fmt.Errorf("minimum confidence must be between 1 and 100")
	}
	return nil
}

func matchesCategories(categories, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	for _, category := range categories {
		for _, filter := range filters {
			if strings.EqualFold(category, strings.TrimSpace(filter)) {
				return true
			}
		}
	}
	return false
}

func canonicalURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return value
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Fragment = ""
	return parsed.String()
}

func sameHost(origin *url.URL, candidate string) bool {
	if origin == nil {
		return false
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	return strings.EqualFold(origin.Host, parsed.Host)
}

func safeCrawlURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	lower := strings.ToLower(parsed.EscapedPath() + "?" + parsed.RawQuery)
	for _, unsafeTerm := range []string{
		"logout", "log-out", "signout", "sign-out", "delete", "remove", "destroy", "revoke",
		"reset", "deactivate", "disable", "terminate", "cancel", "purge", "unsubscribe",
	} {
		if strings.Contains(lower, unsafeTerm) {
			return false
		}
	}
	switch strings.ToLower(path.Ext(parsed.Path)) {
	case ".7z", ".avi", ".dmg", ".doc", ".docx", ".exe", ".gif", ".gz", ".ico", ".jpeg", ".jpg",
		".mov", ".mp3", ".mp4", ".pdf", ".png", ".ppt", ".pptx", ".rar", ".svg", ".tar", ".tgz",
		".webm", ".webp", ".xls", ".xlsx", ".zip":
		return false
	default:
		return true
	}
}

func looksLikeHTML(contentType string, body []byte) bool {
	lowerContentType := strings.ToLower(contentType)
	if strings.Contains(lowerContentType, "text/html") || strings.Contains(lowerContentType, "application/xhtml+xml") {
		return true
	}
	trimmed := strings.TrimSpace(string(body[:min(len(body), 512)]))
	trimmed = strings.ToLower(trimmed)
	return strings.HasPrefix(trimmed, "<!doctype html") || strings.HasPrefix(trimmed, "<html") || strings.HasPrefix(trimmed, "<head")
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func retryableError(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

func retryDelay(attempt int, response *http.Response) time.Duration {
	if response != nil {
		if retryAfter := response.Header.Get("Retry-After"); retryAfter != "" {
			if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds >= 0 {
				return min(time.Duration(seconds)*time.Second, 30*time.Second)
			}
			if when, err := http.ParseTime(retryAfter); err == nil {
				return min(max(time.Until(when), 0), 30*time.Second)
			}
		}
	}
	return min(250*time.Millisecond*time.Duration(1<<attempt), 2*time.Second)
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func findTitle(body []byte) string {
	tokenizer := html.NewTokenizer(strings.NewReader(string(body)))
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			return ""
		case html.StartTagToken:
			token := tokenizer.Token()
			if strings.EqualFold(token.Data, "title") && tokenizer.Next() == html.TextToken {
				return strings.Join(strings.Fields(tokenizer.Token().Data), " ")
			}
		}
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func markUnprocessed(results []Result, targets []Target, err error) {
	for index := range results {
		if results[index].Input == "" {
			results[index] = Result{
				Input:        targets[index].Input,
				Technologies: make([]Technology, 0),
				Error:        err.Error(),
			}
		}
	}
}

type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newRateLimiter(rate float64) *rateLimiter {
	limiter := &rateLimiter{}
	if rate > 0 {
		limiter.interval = time.Duration(float64(time.Second) / rate)
	}
	return limiter
}

func (l *rateLimiter) Wait(ctx context.Context) error {
	if l.interval <= 0 {
		return nil
	}

	l.mu.Lock()
	now := time.Now()
	reserved := now
	if l.next.After(now) {
		reserved = l.next
	}
	l.next = reserved.Add(l.interval)
	l.mu.Unlock()

	wait := time.Until(reserved)
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
