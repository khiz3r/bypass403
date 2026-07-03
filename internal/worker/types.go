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
	Error       error
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
	PayloadsDir   string // optional on-disk payload override dir (passed to payloads.Load)
	OutputFile    string // optional file to write the report output to

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