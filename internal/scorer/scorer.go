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
	// Include BodySnippet so HTML-challenge WAFs (Cloudflare "Attention Required",
	// Imperva challenge) are caught even when they don't set identifying headers.
	combined := strings.ToLower(r.ContentType) + " " + r.BodySnippet
	for k, v := range r.RawHeaders {
		combined += " " + strings.ToLower(k) + " " + strings.ToLower(v)
	}
	for _, sig := range wafBodyStrings {
		if strings.Contains(combined, sig) {
			sr.IsWAF = true
			break
		}
	}
	// Also tag if the detected WAF list is non-empty, baseline was 403, and
	// status didn't change — avoids penalising real 200s when baseline is 200.
	if len(cfg.WAFFingerprints) > 0 && cfg.BaseStatus == 403 && r.StatusCode == cfg.BaseStatus {
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
	// For raw requests, r.Req.URL holds only the base (e.g. "https://host");
	// reconstruct the full wire target from RawTarget so the curl command
	// actually replays the byte-exact path that triggered the bypass.
	curlURL := r.Req.URL
	if r.Req.UseRaw && r.Req.RawTarget != "" {
		curlURL = r.Req.URL + r.Req.RawTarget
	}
	sb.WriteString(fmt.Sprintf(" '%s'", curlURL))
	return sb.String()
}

// Print scores all results and outputs a ranked table.
func Print(results []worker.Result, cfg *worker.Config) {
	filtered := 0
	var scored []ScoredResult
	for _, r := range results {
		// -fc: drop matching status codes before they're even scored, so
		// they don't consume a HIGH/MEDIUM/LOW slot or clutter the report.
		if r.Error == nil && cfg.FilterCodes.Match(r.StatusCode) {
			filtered++
			continue
		}
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
	summary := fmt.Sprintf("\n[*] Done. %d results | HIGH: %d | MEDIUM: %d | LOW: %d",
		len(scored), len(high), len(medium), len(low))
	if filtered > 0 {
		summary += fmt.Sprintf(" | filtered: %d (-fc)", filtered)
	}
	builder.WriteString(summary + "\n")

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
	w.WriteString(fmt.Sprintf("\n── %s (%d) ──\n\n", label, len(items)))
	for _, sr := range items {
		r := sr.Result
		wafTag := ""
		if sr.IsWAF {
			wafTag = " [WAF]"
		}

		// Header line: only join the parts that actually have content, so we
		// never end up with a dangling "| " when a field is empty.
		headParts := []string{
			fmt.Sprintf("[%s]%s %d", sr.Confidence, wafTag, r.StatusCode),
			fmt.Sprintf("%d bytes", r.BodyLen),
		}
		if r.Req.Description != "" {
			headParts = append(headParts, r.Req.Description)
		}
		w.WriteString("  " + strings.Join(headParts, " | ") + "\n")

		if r.Req.Value != "" {
			w.WriteString(fmt.Sprintf("    value  : %s\n", r.Req.Value))
		} else if len(r.Req.Headers) > 0 {
			parts := make([]string, 0, len(r.Req.Headers))
			for k, v := range r.Req.Headers {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			w.WriteString(fmt.Sprintf("    header : %s\n", strings.Join(parts, ", ")))
		}

		if len(sr.Reasons) > 0 {
			w.WriteString(fmt.Sprintf("    signal : %s\n", strings.Join(sr.Reasons, "; ")))
		}

		if sr.CurlCmd != "" && !cfg.Silent {
			w.WriteString(fmt.Sprintf("    curl   : %s\n", sr.CurlCmd))
		}
		w.WriteString("\n")
	}
}
