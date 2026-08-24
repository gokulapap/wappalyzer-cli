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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"golang.org/x/net/html"
)

type Scanner struct {
	config          Config
	client          *http.Client
	detector        *wappalyzer.Wappalyze
	technologyNames map[string]struct{}
	limiter         *rateLimiter
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

	technologyNames := make(map[string]struct{}, len(detector.GetFingerprints().Apps))
	for name := range detector.GetFingerprints().Apps {
		technologyNames[name] = struct{}{}
	}

	return &Scanner{
		config:          config,
		client:          client,
		detector:        detector,
		technologyNames: technologyNames,
		limiter:         newRateLimiter(config.RatePerSecond),
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
		result.Technologies = s.detect(response.Header, body)
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

func (s *Scanner) detect(headers http.Header, body []byte) []Technology {
	detected := s.detector.FingerprintWithInfo(headers, body)
	technologies := make([]Technology, 0, len(detected))
	for detectedName, info := range detected {
		name, version := splitTechnologyVersion(detectedName, s.technologyNames)
		categories := append([]string(nil), info.Categories...)
		sort.Strings(categories)
		if !matchesCategories(categories, s.config.Categories) {
			continue
		}
		technologies = append(technologies, Technology{
			Name:        name,
			Version:     version,
			Categories:  categories,
			Description: info.Description,
			Website:     info.Website,
			CPE:         info.CPE,
		})
	}
	sort.Slice(technologies, func(i, j int) bool {
		if technologies[i].Name == technologies[j].Name {
			return technologies[i].Version < technologies[j].Version
		}
		return technologies[i].Name < technologies[j].Name
	})
	return technologies
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
	return nil
}

func splitTechnologyVersion(value string, knownNames map[string]struct{}) (string, string) {
	if _, known := knownNames[value]; known {
		return value, ""
	}
	for separator := strings.LastIndex(value, ":"); separator >= 0; separator = strings.LastIndex(value[:separator], ":") {
		name := value[:separator]
		if _, known := knownNames[name]; known {
			return name, value[separator+1:]
		}
	}
	return value, ""
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
