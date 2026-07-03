package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	payloads "bypass403/payloads"
	"bypass403/internal/modules"
	"bypass403/internal/scorer"
	"bypass403/internal/worker"
)

const banner = `
██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗██╗  ██╗ ██████╗ ██████╗ 
██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██╔═████╗╚════██╗
██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗███████║██║██╔██║ █████╔╝
██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║╚════██║████╔╝██║ ╚═══██╗
██████╔╝   ██║   ██║     ██║  ██║███████║███████║     ██║╚██████╔╝██████╔╝
╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝     ╚═╝ ╚═════╝ ╚═════╝ 
                                                    by Khiz3r | 403 Bypasser
`

const defaultProxy = "http://127.0.0.1:8080"

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func printUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: bypass403 -u <url> [flags]\n")
	fmt.Fprintf(flag.CommandLine.Output(), "\nFlags:\n")
	flag.PrintDefaults()
}

func main() {
	var customHeaders multiFlag

	url := flag.String("u", "", "Target URL (required)")
	threads := flag.Int("t", 3, "Number of concurrent threads")
	delay := flag.Int("d", 500, "Delay between requests in ms")
	proxy := flag.String("proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080). Use -proxy with no value to use the default proxy")
	skipTLS := flag.Bool("k", false, "Skip TLS verification")
	silent := flag.Bool("silent", false, "Print findings only")
	debug := flag.Bool("debug", false, "Verbose output — print every request/response")
	wayback := flag.Bool("wayback", false, "Enable Wayback Machine CDX lookup")
	outputFile := flag.String("o", "", "Write the report output to this text file")
	flag.Var(&customHeaders, "H", "Custom header. Repeat the flag to add multiple headers (e.g. -H 'X-Test: 1' -H 'Cookie: a=b')")
	flag.Usage = printUsage
	flag.Parse()

	if *url == "" {
		printUsage()
		os.Exit(1)
	}

	proxyValue := *proxy
	if proxyValue == "" {
		proxyValue = defaultProxy
	}

	if !*silent {
		fmt.Print(banner)
		fmt.Printf("[*] Target  : %s\n", *url)
		fmt.Printf("[*] Threads : %d\n", *threads)
		fmt.Printf("[*] Delay   : %dms\n", *delay)
		fmt.Printf("[*] Proxy   : %s\n", proxyDisplay(proxyValue))
		fmt.Printf("[*] TLS skip: %v\n", *skipTLS)
		fmt.Printf("[*] Wayback : %v\n", *wayback)
		if len(customHeaders) > 0 {
			fmt.Printf("[*] Headers : %s\n", customHeaders.String())
		}
		fmt.Println()
	}

	cfg := &worker.Config{
		URL:           *url,
		Threads:       *threads,
		DelayMS:       *delay,
		Proxy:         proxyValue,
		SkipTLS:       *skipTLS,
		Silent:        *silent,
		Debug:         *debug,
		Wayback:       *wayback,
		CustomHeaders: []string(customHeaders),
		OutputFile:    *outputFile,
	}

	db, err := payloads.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load payloads: %v\n", err)
		os.Exit(1)
	}

	// Build request queue from all modules
	requests := modules.Build(*url, *wayback, db)

	// Run worker pool
	results := worker.Run(cfg, requests)

	// Score and print
	scorer.Print(results, cfg)
}

func proxyDisplay(p string) string {
	if p == "" {
		return "none"
	}
	return p
}
