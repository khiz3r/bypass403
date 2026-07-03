package scorer

import (
	"fmt"
	"math"
	"os"
	"strings"

	"bypass403/internal/worker"
)

// Confidence tiers
const (
	HIGH   = "HIGH"
	MEDIUM = "MEDIUM"
	LOW    = "LOW"
)

// wafBodyStrings are substrings that indicate a WAF-generated 403, not an app-level one.
// These are checked against the result's ContentType + RawHeaders to tag and suppress.
var wafBodyStrings = []string{
	"cloudflare", "cf-ray", "attention required",
	"cloudfront", "error: the request could not be satisfied",
	"akamaighost", "reference #",
	"sucuri website firewall",
	"incapsula incident",
}

type ScoredResult struct {
	Result     worker.Result
	Score      int
	Confidence string
	Reasons    []string
	IsWAF      bool
	CurlCmd    string
}

// Score evaluates a Result against the baseline and calibration data.
func Score(r worker.Result, cfg *worker.Config) ScoredResult {
	sr := ScoredResult{Result: r}

	if r.Error != nil {
		return sr
	}

	// --- WAF fingerprint check ---
	combined := strings.ToLower(r.ContentType)
	for k, v := range r.RawHeaders {
		combined += " " + strings.ToLower(k) + " " + strings.ToLower(v)
	}
	for _, sig := range wafBodyStrings {
		if strings.Contains(combined, sig) {
			sr.IsWAF = true
			break
		}
	}
	// Also tag if the detected WAF list is non-empty and status didn't change
	if len(cfg.WAFFingerprints) > 0 && r.StatusCode == cfg.BaseStatus {
		sr.IsWAF = true
	}

	// --- Scoring ---
	points := 0
	var reasons []string

	// 1. Status code changed from 403
	if cfg.BaseStatus == 403 && r.StatusCode != 403 {
		switch {
		case r.StatusCode == 200:
			points += 50
			reasons = append(reasons, "status 403→200")
		case r.StatusCode >= 200 && r.StatusCode < 300:
			points += 40
			reasons = append(reasons, fmt.Sprintf("status 403→%d", r.StatusCode))
		case r.StatusCode == 301 || r.StatusCode == 302:
			points += 20
			reasons = append(reasons, fmt.Sprintf("redirect %d", r.StatusCode))
		case r.StatusCode == 500:
			points += 5
			reasons = append(reasons, "status 500 (possible info)")
		}
	} else if r.StatusCode == cfg.BaseStatus {
		// Same status as baseline — very low signal
		points -= 10
	}

	// 2. Body hash changed from baseline
	if r.BodyHash != cfg.BaseHash && r.BodyHash != "" {
		points += 20
		reasons = append(reasons, "body hash changed")
	}

	// 3. Body length delta — significant change is a good signal
	lenDelta := r.BodyLen - cfg.BaseLen
	absDelta := int(math.Abs(float64(lenDelta)))
	switch {
	case absDelta > 5000:
		points += 20
		reasons = append(reasons, fmt.Sprintf("len Δ%+d bytes", lenDelta))
	case absDelta > 500:
		points += 10
		reasons = append(reasons, fmt.Sprintf("len Δ%+d bytes", lenDelta))
	case absDelta < 50 && r.StatusCode == 200:
		// 200 with same tiny body as 403 — likely false positive (same "Access Denied" page)
		points -= 15
		reasons = append(reasons, "body len ~same (possible FP)")
	}

	// 4. Body length same as calibration 404 — likely a generic error page
	if cfg.CalibLen > 0 && absDelta == 0 && r.BodyLen == cfg.CalibLen {
		points -= 20
		reasons = append(reasons, "body matches 404 calib (FP)")
	}

	// 5. Content-Type changed
	if r.ContentType != cfg.BaseContentType && r.ContentType != "" {
		points += 10
		reasons = append(reasons, fmt.Sprintf("content-type: %s", r.ContentType))
	}

	// 6. WAF-generated response — penalise
	if sr.IsWAF {
		points -= 30
		reasons = append(reasons, "WAF-generated response")
	}

	sr.Score = points
	switch {
	case points >= 60:
		sr.Confidence = HIGH
	case points >= 25:
		sr.Confidence = MEDIUM
	default:
		sr.Confidence = LOW
	}

	// Build curl replay for medium+ confidence
	if points >= 25 {
		sr.CurlCmd = buildCurl(r)
	}

	return sr
}

func buildCurl(r worker.Result) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("curl -sk -X %s", r.Req.Method))
	for k, v := range r.Req.Headers {
		sb.WriteString(fmt.Sprintf(" -H '%s: %s'", k, v))
	}
	sb.WriteString(fmt.Sprintf(" '%s'", r.Req.URL))
	return sb.String()
}

// Print scores all results and outputs a ranked table.
func Print(results []worker.Result, cfg *worker.Config) {
	var scored []ScoredResult
	for _, r := range results {
		scored = append(scored, Score(r, cfg))
	}

	var builder strings.Builder

	// Partition
	var high, medium, low, errors []ScoredResult
	for _, sr := range scored {
		if sr.Result.Error != nil {
			errors = append(errors, sr)
			continue
		}
		if sr.IsWAF && sr.Score < 25 {
			// Silent-suppress pure WAF noise unless score still climbed
			continue
		}
		switch sr.Confidence {
		case HIGH:
			high = append(high, sr)
		case MEDIUM:
			medium = append(medium, sr)
		default:
			low = append(low, sr)
		}
	}

	printSection(&builder, "HIGH CONFIDENCE", high, cfg)
	printSection(&builder, "MEDIUM CONFIDENCE", medium, cfg)

	if !cfg.Silent {
		printSection(&builder, "LOW CONFIDENCE", low, cfg)
		if len(errors) > 0 {
			builder.WriteString(fmt.Sprintf("\n[!] %d requests errored (network/TLS)\n", len(errors)))
		}
	}

	// Summary
	builder.WriteString(fmt.Sprintf("\n[*] Done. %d results | HIGH: %d | MEDIUM: %d | LOW: %d\n",
		len(scored), len(high), len(medium), len(low)))

	output := builder.String()
	fmt.Print(output)
	if cfg.OutputFile != "" {
		if err := os.WriteFile(cfg.OutputFile, []byte(output), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "[!] failed to write output file: %v\n", err)
		}
	}
}

func printSection(w *strings.Builder, label string, items []ScoredResult, cfg *worker.Config) {
	if len(items) == 0 {
		return
	}
	w.WriteString(fmt.Sprintf("\n── %s (%d) ──\n", label, len(items)))
	for _, sr := range items {
		r := sr.Result
		wafTag := ""
		if sr.IsWAF {
			wafTag = " [WAF]"
		}
		valueText := ""
		if r.Req.Value != "" {
			valueText = " | value: " + r.Req.Value
		} else if len(r.Req.Headers) > 0 {
			parts := make([]string, 0, len(r.Req.Headers))
			for k, v := range r.Req.Headers {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			valueText = " | values: " + strings.Join(parts, ", ")
		}
		w.WriteString(fmt.Sprintf("  [%s]%s %d | %d bytes | %s%s | %s\n",
			sr.Confidence, wafTag,
			r.StatusCode, r.BodyLen,
			r.Req.Description,
			valueText,
			strings.Join(sr.Reasons, "; "),
		))
		if sr.CurlCmd != "" && !cfg.Silent {
			w.WriteString(fmt.Sprintf("    → %s\n", sr.CurlCmd))
		}
	}
}
