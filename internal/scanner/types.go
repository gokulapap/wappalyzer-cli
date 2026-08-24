package scanner

import "time"

const DefaultUserAgent = "wappy/dev (+https://github.com/gokulapap/wappalyzer-cli)"

type Config struct {
	Concurrency     int
	Timeout         time.Duration
	Retries         int
	MaxBodyBytes    int64
	MaxRedirects    int
	RatePerSecond   float64
	UserAgent       string
	Headers         map[string][]string
	ProxyURL        string
	InsecureTLS     bool
	FollowRedirects bool
	Scheme          string
	FingerprintFile string
	Categories      []string
	CrawlPages      int
	FetchAssets     bool
	MaxAssets       int
	AssetScope      string
	MinConfidence   int
}

type Target struct {
	Input      string
	Candidates []string
}

type Technology struct {
	Name        string     `json:"name"`
	Version     string     `json:"version,omitempty"`
	Confidence  int        `json:"confidence"`
	Categories  []string   `json:"categories"`
	Description string     `json:"description,omitempty"`
	Website     string     `json:"website,omitempty"`
	CPE         string     `json:"cpe,omitempty"`
	Evidence    []Evidence `json:"evidence,omitempty"`
}

type Evidence struct {
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
	URL   string `json:"url,omitempty"`
}

type Result struct {
	Input         string       `json:"input"`
	URL           string       `json:"url,omitempty"`
	FinalURL      string       `json:"final_url,omitempty"`
	StatusCode    int          `json:"status_code,omitempty"`
	Title         string       `json:"title,omitempty"`
	Technologies  []Technology `json:"technologies"`
	Server        string       `json:"server,omitempty"`
	ContentType   string       `json:"content_type,omitempty"`
	TLSVersion    string       `json:"tls_version,omitempty"`
	BodyBytes     int64        `json:"body_bytes,omitempty"`
	Truncated     bool         `json:"truncated,omitempty"`
	PagesScanned  int          `json:"pages_scanned"`
	AssetsScanned int          `json:"assets_scanned,omitempty"`
	PartialErrors []string     `json:"partial_errors,omitempty"`
	DurationMS    int64        `json:"duration_ms"`
	Error         string       `json:"error,omitempty"`
}
