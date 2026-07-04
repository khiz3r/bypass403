package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"bypass403/internal/modules"
	"bypass403/internal/scorer"
	"bypass403/internal/worker"
	payloads "bypass403/payloads"
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

// ANSI colors - just enough to make the "target isn't even 403ing" warning
// stand out from the normal [*] info lines.
const (
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
)

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
	proxy := flag.String("proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080). Pass -proxy=burp to use "+defaultProxy+". Omit flag to send direct.")
	skipTLS := flag.Bool("k", false, "Skip TLS verification")
	silent := flag.Bool("silent", false, "Print findings only")
	debug := flag.Bool("debug", false, "Verbose output — print every request/response")
	wayback := flag.Bool("wayback", false, "Enable Wayback Machine CDX lookup")
	outputFile := flag.String("o", "", "Write the report output to this text file")
	filterCodes := flag.String("fc", "", "Filter out response status codes from the report. Comma-separated, ranges supported, e.g. -fc 404,400-410")
	flag.Var(&customHeaders, "H", "Custom header. Repeat the flag to add multiple headers (e.g. -H 'X-Test: 1' -H 'Cookie: a=b')")
	flag.Usage = printUsage
	flag.Parse()

	if *url == "" {
		printUsage()
		os.Exit(1)
	}

	proxyValue := *proxy
	if proxyValue == "burp" {
		proxyValue = defaultProxy
	}

	fcRanges, err := worker.ParseCodeFilter(*filterCodes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
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
		FilterCodes:   fcRanges,
	}

	printHeader := func() {
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
		if *filterCodes != "" {
			fmt.Printf("[*] Filter  : %s (status codes hidden)\n", *filterCodes)
		}
		fmt.Println()
	}

	if !*silent {
		printHeader()
	}

	// --- Baseline check happens BEFORE we build/run any bypass payloads. ---
	// There's nothing to "bypass" if the target isn't returning 403 in the
	// first place, so we send exactly one request up front and gate the
	// entire sweep on it.
	client := worker.NewClient(cfg)
	worker.SendBaseline(client, cfg)

	notProtected := cfg.BaseStatus != 403
	if notProtected {
		// Force the header through even with -silent, since it's the only
		// context the user gets before we bail out.
		if *silent {
			printHeader()
		}

		fmt.Printf("[*] Baseline: %d | %d bytes | hash=%s\n",
			cfg.BaseStatus, cfg.BaseLen, shortHash(cfg.BaseHash))

		warning := fmt.Sprintf(
			"[!] Baseline did not return 403 (got %d) - this endpoint doesn't appear to be access-restricted, so there's nothing to bypass. Skipping all bypass techniques.",
			cfg.BaseStatus,
		)
		fmt.Printf("%s%s%s\n", colorYellow, warning, colorReset)

		if cfg.OutputFile != "" {
			if err := os.WriteFile(cfg.OutputFile, []byte(warning+"\n"), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "[!] failed to write output file: %v\n", err)
			}
		}
		return
	}

	if !*silent {
		fmt.Printf("[*] Baseline: %d | %d bytes | hash=%s\n",
			cfg.BaseStatus, cfg.BaseLen, shortHash(cfg.BaseHash))
	}

	db, err := payloads.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load payloads: %v\n", err)
		os.Exit(1)
	}

	// Build request queue from all modules
	requests := modules.Build(*url, *wayback, *silent, db)

	// Run calibration + worker pool sweep
	results := worker.RunSweep(client, cfg, requests)

	// Score and print
	scorer.Print(results, cfg)
}

func shortHash(h string) string {
	if len(h) < 8 {
		return h
	}
	return h[:8]
}

func proxyDisplay(p string) string {
	if p == "" {
		return "none"
	}
	return p
}
