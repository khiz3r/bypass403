package worker

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// doRawRequestOnce sends a request with a literal, unescaped request-line
// target over a raw TCP/TLS socket, using http.ReadResponse only to parse
// the response back into Go structures.
//
// This is the architectural fix for bypass403's biggest blind spot:
// net/http's client re-derives the wire path via url.URL.EscapedPath() /
// RequestURI(), which silently collapses or re-encodes sequences like
// "%2e%2e", "//", ";", and raw control bytes before they ever leave the
// machine. Everything downstream (scoring, hashing, WAF fingerprinting) is
// unaffected — only how the bytes reach the wire changes.
//
// Known limitation: raw-mode requests bypass cfg.Proxy. Full CONNECT-tunnel
// handling for raw paths is out of scope. For Burp triage, run a second
// non-raw pass through -proxy, or point Burp's upstream listener directly
// at the target.
func doRawRequestOnce(cfg *Config, req Request) Result {
	target, err := url.Parse(cfg.URL)
	if err != nil {
		return Result{Req: req, Error: fmt.Errorf("raw: parsing base URL: %w", err)}
	}

	host := target.Host
	if !strings.Contains(host, ":") {
		if target.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	dialer := net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	if target.Scheme == "https" {
		conn, err = tls.DialWithDialer(&dialer, "tcp", host, &tls.Config{
			InsecureSkipVerify: cfg.SkipTLS, //nolint:gosec
			ServerName:         target.Hostname(),
		})
	} else {
		conn, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		return Result{Req: req, Error: fmt.Errorf("raw: dial: %w", err)}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	method := req.Method
	if method == "" {
		method = "GET"
	}
	rawTarget := req.RawTarget
	if rawTarget == "" {
		rawTarget = "/"
	}

	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteByte(' ')
	sb.WriteString(rawTarget) // verbatim — zero escaping or cleaning
	sb.WriteString(" HTTP/1.1\r\n")
	sb.WriteString("Host: " + target.Hostname() + "\r\n")
	sb.WriteString("User-Agent: bypass403/1.0\r\n")
	sb.WriteString("Connection: close\r\n")

	sentHeaders := map[string]bool{"host": true, "user-agent": true, "connection": true}
	for k, v := range req.Headers {
		sb.WriteString(k + ": " + v + "\r\n")
		sentHeaders[strings.ToLower(k)] = true
	}
	for _, h := range cfg.CustomHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			if sentHeaders[strings.ToLower(name)] {
				continue // module-specific header wins; don't clobber
			}
			sb.WriteString(name + ": " + strings.TrimSpace(parts[1]) + "\r\n")
		}
	}
	sb.WriteString("\r\n")

	if cfg.Debug {
		fmt.Printf("\n>> [RAW] %s", sb.String())
	}

	if _, err := conn.Write([]byte(sb.String())); err != nil {
		return Result{Req: req, Error: fmt.Errorf("raw: write: %w", err)}
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return Result{Req: req, Error: fmt.Errorf("raw: read response: %w", err)}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	hash := fmt.Sprintf("%x", md5.Sum(body))

	rawHeaders := make(map[string]string)
	for k, v := range resp.Header {
		rawHeaders[k] = strings.Join(v, ", ")
	}

	if cfg.Debug {
		fmt.Printf("<< [RAW] HTTP %d | len=%d | hash=%s\n", resp.StatusCode, len(body), hash[:8])
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