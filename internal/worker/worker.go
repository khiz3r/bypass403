package worker

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// wafSignatures maps a WAF label to header/content substrings that identify it.
var wafSignatures = map[string][]string{
	"Cloudflare": {"cloudflare", "cf-ray", "__cfduid", "attention required"},
	"CloudFront": {"cloudfront", "error: the request could not be satisfied"},
	"Akamai":     {"akamaighost", "reference #"},
	"Sucuri":     {"sucuri website firewall", "sucuri.net"},
	"Imperva":    {"incapsula incident", "_incap_ses_"},
}

// detectWAF scans a Result's headers and content-type for known WAF signatures.
// Body content is not stored to avoid memory cost; header signals cover the
// common WAF vendors sufficiently.
func detectWAF(r Result) []string {
	combined := strings.ToLower(r.ContentType)
	for k, v := range r.RawHeaders {
		combined += " " + strings.ToLower(k) + " " + strings.ToLower(v)
	}
	var found []string
	for waf, sigs := range wafSignatures {
		for _, sig := range sigs {
			if strings.Contains(combined, sig) {
				found = append(found, waf)
				break
			}
		}
	}
	return found
}

func buildClient(cfg *Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.SkipTLS}, //nolint:gosec
	}
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // never follow redirects
		},
	}
}

// doRequest dispatches to the raw socket client or the stdlib client based on
// req.UseRaw, and retries up to 3 times on HTTP 429 with exponential backoff.
//
// BUG FIX: previously doRequest always called doRequestOnce (stdlib net/http),
// meaning every req.UseRaw request was silently normalized by Go's URL parser
// and the raw client was dead code. The branch below is the fix.
func doRequest(client *http.Client, cfg *Config, req Request) Result {
	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		var result Result
		if req.UseRaw {
			// Send byte-exact request line over raw TCP/TLS socket.
			// Note: raw requests do not traverse cfg.Proxy (documented limitation).
			result = doRawRequestOnce(cfg, req)
		} else {
			result = doRequestOnce(client, cfg, req)
		}

		if result.StatusCode != 429 || attempt == maxRetries-1 {
			return result
		}
		// Exponential backoff: 2s, 4s, 8s
		backoff := time.Duration(2<<uint(attempt)) * time.Second
		if !cfg.Silent {
			fmt.Printf("[!] 429 on %s — backing off %s\n", req.URL, backoff)
		}
		time.Sleep(backoff)
	}
	// Unreachable, but satisfies the compiler.
	return Result{Req: req, Error: fmt.Errorf("max retries exceeded after 429")}
}

func doRequestOnce(client *http.Client, cfg *Config, req Request) Result {
	httpReq, err := http.NewRequest(req.Method, req.URL, nil)
	if err != nil {
		return Result{Req: req, Error: err}
	}
	httpReq.Header.Set("User-Agent", "bypass403/1.0")

	// Module-specific headers
	for k, v := range req.Headers {
		httpReq.Header.Add(k, v)
	}

	// User-supplied headers applied last so they can override module headers.
	for _, h := range cfg.CustomHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			httpReq.Header.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	if cfg.Debug {
		fmt.Printf("\n>> %s %s\n", req.Method, req.URL)
		for k, v := range httpReq.Header {
			fmt.Printf(">>   %s: %s\n", k, strings.Join(v, ", "))
		}
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return Result{Req: req, Error: err}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	hash := fmt.Sprintf("%x", md5.Sum(body))

	rawHeaders := make(map[string]string)
	for k, v := range resp.Header {
		rawHeaders[k] = strings.Join(v, ", ")
	}

	if cfg.Debug {
		fmt.Printf("<< HTTP %d | len=%d | hash=%s\n", resp.StatusCode, len(body), hash[:8])
	}

	return Result{
		Req:         req,
		StatusCode:  resp.StatusCode,
		BodyLen:     len(body),
		BodyHash:    hash,
		ContentType: resp.Header.Get("Content-Type"),
		RawHeaders:  rawHeaders,
	}
}

// Run executes the full bypass sweep:
//  1. Baseline request to establish the reference status/body.
//  2. Calibration request against a known-nonexistent path to measure 404 body size.
//  3. Worker pool dispatches all requests concurrently, respecting -t and -d flags.
func Run(cfg *Config, requests []Request) []Result {
	client := buildClient(cfg)

	// --- Baseline ---
	if !cfg.Silent {
		fmt.Println("[*] Sending baseline request...")
	}
	baseline := doRequest(client, cfg, Request{
		Method:      "GET",
		URL:         cfg.URL,
		Headers:     map[string]string{},
		Description: "baseline",
		Module:      "baseline",
	})
	cfg.BaseStatus = baseline.StatusCode
	cfg.BaseLen = baseline.BodyLen
	cfg.BaseHash = baseline.BodyHash
	cfg.BaseContentType = baseline.ContentType
	cfg.WAFFingerprints = detectWAF(baseline)

	if !cfg.Silent {
		fmt.Printf("[*] Baseline: %d | %d bytes | hash=%s\n",
			cfg.BaseStatus, cfg.BaseLen, cfg.BaseHash[:8])
		if len(cfg.WAFFingerprints) > 0 {
			fmt.Printf("[*] WAF detected: %s\n", strings.Join(cfg.WAFFingerprints, ", "))
		}
		fmt.Println()
	}

	// --- Calibration (non-existent path) ---
	calResult := doRequest(client, cfg, Request{
		Method:      "GET",
		URL:         cfg.URL + "/bypass403_calib_f0f0f0f0f0",
		Headers:     map[string]string{},
		Description: "calibration",
		Module:      "calibration",
	})
	cfg.CalibLen = calResult.BodyLen
	if !cfg.Silent {
		fmt.Printf("[*] Calibration 404 len: %d bytes\n\n", cfg.CalibLen)
	}

	// --- Worker pool ---
	// Buffer channels to the full queue size so producers never block.
	jobCh := make(chan Request, len(requests))
	resultCh := make(chan Result, len(requests))

	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range jobCh {
				if cfg.DelayMS > 0 {
					time.Sleep(time.Duration(cfg.DelayMS) * time.Millisecond)
				}
				resultCh <- doRequest(client, cfg, req)
			}
		}()
	}

	for _, r := range requests {
		jobCh <- r
	}
	close(jobCh)

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var results []Result
	for r := range resultCh {
		results = append(results, r)
	}
	return results
}