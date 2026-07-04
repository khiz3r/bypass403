package worker

// Request represents a single bypass attempt.
type Request struct {
	Method      string
	URL         string
	Headers     map[string]string
	Value       string // e.g. "/{{PATH_UPPER}}" or header value payload
	Description string // e.g. "Header: X-Original-URL: /admin"
	Module      string // e.g. "headers", "path", "method"

	// UseRaw, when true, tells the worker to send this request over a raw
	// TCP/TLS socket (rawclient.go) instead of net/http, preserving the
	// byte-exact request-line target. net/http re-derives the wire path via
	// url.URL.EscapedPath()/RequestURI(), silently collapsing/re-encoding
	// sequences like "%2e%2e", "//", ";", and raw control bytes before they
	// ever leave the machine. RawTarget MUST be set whenever UseRaw is true.
	UseRaw    bool
	RawTarget string // literal request-line target, e.g. "/admin%2e%2e/", "/admin#.png"
}

// Result is the outcome of a single Request.
type Result struct {
	Req         Request
	StatusCode  int
	BodyLen     int
	BodyHash    string
	ContentType string
	RawHeaders  map[string]string
	// BodySnippet holds the first 512 bytes of the response body, lowercased,
	// used for WAF signature matching without retaining the full body in memory.
	BodySnippet string
	Error       error
}

// CodeRange represents an inclusive status-code range for the -fc filter,
// e.g. "404" becomes {404, 404} and "400-410" becomes {400, 410}.
type CodeRange struct {
	Low  int
	High int
}

// CodeRanges is a set of CodeRange used to filter out noisy status codes
// via -fc (e.g. "404,400-410").
type CodeRanges []CodeRange

// Match reports whether code falls inside any of the configured ranges.
func (rs CodeRanges) Match(code int) bool {
	for _, r := range rs {
		if code >= r.Low && code <= r.High {
			return true
		}
	}
	return false
}

// Config holds all runtime flags plus baseline/calibration state filled in
// by worker.Run before the main sweep begins.
type Config struct {
	URL           string
	Threads       int
	DelayMS       int
	Proxy         string
	SkipTLS       bool
	Silent        bool
	Debug         bool
	Wayback       bool
	CustomHeaders []string
	PayloadsDir   string     // optional on-disk payload override dir (passed to payloads.Load)
	OutputFile    string     // optional file to write the report output to
	FilterCodes   CodeRanges // -fc: status codes/ranges to drop from the report entirely

	// Baseline — filled by Run() before the sweep.
	BaseStatus      int
	BaseLen         int
	BaseHash        string
	BaseContentType string

	// Calibration: body length of a known-404 path.
	CalibLen int

	// WAF fingerprint labels detected in the baseline response.
	WAFFingerprints []string
}
