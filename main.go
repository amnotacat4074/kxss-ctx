package main

// kxss-ctx: a context-aware reflected-XSS scanner.
//
// It improves on kxss by classifying where a reflection lands (HTML text,
// quoted/unquoted attribute, script string, comment, style, ...), probing only
// the characters that can break out of that context, parsing CSP, and
// detecting reflection into a redirect Location header.

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// defaultUA is the User-Agent sent when -ua is not given. Tools that send a
// browser UA (as kxss does) lie about what is on the wire; this advertises the
// tool so a defender can identify the traffic.
const defaultUA = "kxss-ctx/1.0 (context-aware XSS reflection scanner; +https://github.com/amnotacat4074/kxss-ctx)"

// severityRank orders severities for -min-severity filtering. Anything
// unrecognised ranks below "info" and is therefore suppressed unless the
// threshold is explicitly lowered (it cannot be, so it is suppressed).
var severityRank = map[string]int{
	"info":   0,
	"low":    1,
	"medium": 2,
	"high":   3,
}

// ANSI SGR fragments. Only the severity token is coloured; the rest of the
// line keeps the terminal's default foreground so it stays copy/paste-able.
const (
	ansiReset    = "\x1b[0m"
	ansiHigh     = "\x1b[1;31m" // bold red
	ansiMedium   = "\x1b[33m"   // yellow
	ansiLow      = "\x1b[36m"   // cyan
	ansiInfo     = "\x1b[2;90m" // dim grey
	ansiNoColour = ""
)

func colorFor(severity string) string {
	switch severity {
	case "high":
		return ansiHigh
	case "medium":
		return ansiMedium
	case "low":
		return ansiLow
	case "info":
		return ansiInfo
	}
	return ansiNoColour
}

// colorEnabled resolves the -color flag. Explicit "always" wins over NO_COLOR
// (the operator asked for it); "auto" is disabled by NO_COLOR and by a
// non-terminal stdout. JSON output is never coloured.
func colorEnabled(mode string, jsonOut, noColor, isTTY bool) bool {
	if jsonOut {
		return false
	}
	switch mode {
	case "always":
		return true
	case "never":
		return false
	default: // auto
		return isTTY && !noColor
	}
}

func stdoutIsTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// countingTransport counts every HTTP round trip (including any redirect
// hops) so the final summary can report actual request volume.
type countingTransport struct {
	base http.RoundTripper
	n    *atomic.Int64
}

func (t countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.n.Add(1)
	return t.base.RoundTrip(req)
}

// headerList is a repeatable -H flag ("Name: value").
type headerList struct{ h http.Header }

func (hl *headerList) String() string {
	if hl == nil || len(hl.h) == 0 {
		return ""
	}
	var parts []string
	for name, values := range hl.h {
		for _, v := range values {
			parts = append(parts, name+": "+v)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (hl *headerList) Set(v string) error {
	name, val, ok := strings.Cut(v, ":")
	if !ok {
		return fmt.Errorf("invalid header %q (expected 'Name: value')", v)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("invalid header %q (empty name)", v)
	}
	hl.h.Add(name, strings.TrimSpace(val))
	return nil
}

type task struct {
	url   string
	param string
}

func main() {
	var (
		single      string
		file        string
		jsonOut     bool
		conc        int
		rate        float64
		timeout     time.Duration
		follow      bool
		insecure    bool
		ua          string
		cookie      string
		maxOcc      int
		verbose     bool
		colorMode   string
		minSeverity string
		domain      string
		outDir      string
		reuse       bool
		reconOnly   bool
		maxURLs     int
	)
	headers := &headerList{h: http.Header{}}
	flag.StringVar(&single, "u", "", "single URL to test; must include a query string")
	flag.StringVar(&file, "f", "", "file of URLs, one per line ('-' for stdin)")
	flag.BoolVar(&jsonOut, "json", false, "emit findings as a JSON array")
	flag.IntVar(&conc, "c", 10, "concurrent workers")
	flag.Float64Var(&rate, "rate", 10, "global request rate in requests/second (0 = unlimited)")
	flag.DurationVar(&timeout, "timeout", 15*time.Second, "per-request timeout")
	flag.BoolVar(&follow, "follow", false, "follow redirects (off by default: keeps the scan on-target)")
	flag.BoolVar(&insecure, "k", false, "skip TLS certificate verification")
	flag.StringVar(&ua, "ua", defaultUA, "User-Agent header")
	flag.StringVar(&cookie, "cookie", "", "Cookie header value")
	flag.IntVar(&maxOcc, "max-occ", 3, "max reflections to analyse per parameter")
	flag.BoolVar(&verbose, "v", false, "verbose diagnostics on stderr")
	flag.StringVar(&colorMode, "color", "auto", "colour output: auto|always|never (auto = only on a terminal; NO_COLOR disables auto; -json never colours)")
	flag.StringVar(&minSeverity, "min-severity", "low", "minimum severity to report: info|low|medium|high")
	flag.StringVar(&domain, "d", "", "domain: run subfinder/assetfinder/httpx/katana/gau/uro, then scan every discovered URL with a query string")
	flag.StringVar(&outDir, "o", "", "recon output directory (default ./recon-<domain>)")
	flag.BoolVar(&reuse, "reuse", false, "reuse existing recon files instead of re-running a stage")
	flag.BoolVar(&reconOnly, "recon-only", false, "with -d: build the URL list and stop")
	flag.IntVar(&maxURLs, "max-urls", 0, "cap the number of URLs taken from recon (0 = no cap)")
	flag.Var(headers, "H", "extra request header 'Name: value' (repeatable)")
	flag.Parse()

	if _, ok := severityRank[minSeverity]; !ok {
		fmt.Fprintf(os.Stderr, "kxss-ctx: invalid -min-severity %q (want info, low, medium or high)\n", minSeverity)
		os.Exit(2)
	}
	switch colorMode {
	case "auto", "always", "never":
	default:
		fmt.Fprintf(os.Stderr, "kxss-ctx: invalid -color %q (want auto, always or never)\n", colorMode)
		os.Exit(2)
	}
	noColorEnv := os.Getenv("NO_COLOR") != ""
	useColor := colorEnabled(colorMode, jsonOut, noColorEnv, stdoutIsTerminal())
	minRank := severityRank[minSeverity]

	var urls []string
	var err error
	if domain != "" {
		dir := outDir
		if dir == "" {
			dir = "recon-" + domain
		}
		urls, err = runRecon(domain, dir, reuse, verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kxss-ctx: recon: %v\n", err)
			os.Exit(1)
		}
		if reconOnly {
			fmt.Fprintf(os.Stderr, "kxss-ctx: %d in-scope URLs written under %s\n", len(urls), dir)
			return
		}
		if maxURLs > 0 && len(urls) > maxURLs {
			fmt.Fprintf(os.Stderr, "kxss-ctx: capping %d URLs to %d (-max-urls)\n", len(urls), maxURLs)
			urls = urls[:maxURLs]
		}
	} else {
		urls, err = readURLs(single, file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kxss-ctx: %v\n", err)
			os.Exit(2)
		}
	}
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "kxss-ctx: no URLs supplied (use -d, -u, -f or stdin)")
		flag.Usage()
		os.Exit(2)
	}

	var tasks []task
	seen := make(map[string]bool)
	for _, u := range urls {
		params, perr := urlParams(u)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "kxss-ctx: skipping %s: %v\n", u, perr)
			continue
		}
		if len(params) == 0 {
			fmt.Fprintf(os.Stderr, "kxss-ctx: %s has no query parameters (nothing to test)\n", u)
			continue
		}
		for _, p := range params {
			key := u + "\x00" + p
			if seen[key] {
				continue
			}
			seen[key] = true
			tasks = append(tasks, task{url: u, param: p})
		}
	}
	if len(tasks) == 0 {
		fmt.Fprintln(os.Stderr, "kxss-ctx: no testable (url, parameter) pairs")
		return
	}

	opts := fetchOpts{
		UA:       ua,
		Cookie:   cookie,
		Headers:  headers.h,
		Timeout:  timeout,
		Follow:   follow,
		Insecure: insecure,
	}
	client := newClient(opts)
	var requestCount atomic.Int64
	baseTransport := client.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	client.Transport = countingTransport{base: baseTransport, n: &requestCount}
	lim := newLimiter(rate)

	if conc < 1 {
		conc = 1
	}
	jobs := make(chan task)
	results := make(chan finding, conc*2)
	var wg sync.WaitGroup
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				finds, aerr := analyzeParam(client, opts, t.url, t.param, lim, maxOcc)
				if aerr != nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "kxss-ctx: %s [%s]: %v\n", t.url, t.param, aerr)
					}
					continue
				}
				if len(finds) == 0 && verbose {
					fmt.Fprintf(os.Stderr, "kxss-ctx: %s [%s]: parameter not reflected\n", t.url, t.param)
				}
				for _, f := range finds {
					results <- f
				}
			}
		}()
	}
	go func() {
		for _, t := range tasks {
			jobs <- t
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	var all []finding
	reported := make(map[string]int)
	suppressed := make(map[string]int)
	for f := range results {
		rank, known := severityRank[f.Severity]
		if !known || rank < minRank {
			suppressed[f.Severity]++
			continue
		}
		reported[f.Severity]++
		if jsonOut {
			all = append(all, f)
			continue
		}
		printFinding(os.Stdout, f, useColor)
	}

	printSummary(os.Stderr, len(tasks), requestCount.Load(), minSeverity, reported, suppressed)

	if !jsonOut {
		return
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].URL != all[j].URL {
			return all[i].URL < all[j].URL
		}
		if all[i].Param != all[j].Param {
			return all[i].Param < all[j].Param
		}
		return all[i].Offset < all[j].Offset
	})
	if all == nil {
		all = []finding{}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(all); err != nil {
		fmt.Fprintf(os.Stderr, "kxss-ctx: writing JSON: %v\n", err)
		os.Exit(1)
	}
}

// readURLs collects URLs from -u, -f and stdin (stdin only when neither flag
// is set and stdin is not a terminal).
func readURLs(single, file string) ([]string, error) {
	var raw []string
	if single != "" {
		raw = append(raw, single)
	}
	if file != "" {
		if file == "-" {
			lines, err := scanLines(os.Stdin)
			if err != nil {
				return nil, err
			}
			raw = append(raw, lines...)
		} else {
			f, err := os.Open(file)
			if err != nil {
				return nil, err
			}
			lines, err := scanLines(f)
			f.Close()
			if err != nil {
				return nil, err
			}
			raw = append(raw, lines...)
		}
	}
	if single == "" && file == "" {
		if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice == 0 {
			lines, err := scanLines(os.Stdin)
			if err != nil {
				return nil, err
			}
			raw = append(raw, lines...)
		}
	}

	out := make([]string, 0, len(raw))
	for _, u := range raw {
		u = strings.TrimSpace(u)
		if u == "" || strings.HasPrefix(u, "#") {
			continue
		}
		out = append(out, u)
	}
	return out, nil
}

func scanLines(r io.Reader) ([]string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var out []string
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func printFinding(w io.Writer, f finding, color bool) {
	fmt.Fprintf(w, "[%s] %s  param=%q context=%s", formatSeverity(f.Severity, color), f.URL, f.Param, f.Kind)
	if f.Tag != "" {
		fmt.Fprintf(w, " tag=<%s>", f.Tag)
	}
	if f.Attr != "" {
		fmt.Fprintf(w, " attr=%s", f.Attr)
	}
	if f.ScriptType != "" {
		fmt.Fprintf(w, " script-type=%q", f.ScriptType)
	}
	fmt.Fprintf(w, " offset=%d status=%d\n", f.Offset, f.Status)
	if f.Note != "" {
		fmt.Fprintf(w, "    note:    %s\n", f.Note)
	}
	var literal, encoded []string
	for _, c := range f.Chars {
		switch {
		case c.Literal:
			literal = append(literal, charName(c.Char))
		case c.Encoding != "":
			encoded = append(encoded, charName(c.Char)+"="+c.Encoding)
		}
	}
	fmt.Fprintf(w, "    literal: %s\n", orNone(strings.Join(literal, ", ")))
	fmt.Fprintf(w, "    encoded: %s\n", orNone(strings.Join(encoded, ", ")))
	if f.PoC != "" {
		fmt.Fprintf(w, "    poc:     %s\n", f.PoC)
	}
	if f.CSP != "" {
		fmt.Fprintf(w, "    csp:     %s\n", f.CSP)
	}
	fmt.Fprintf(w, "    verdict: %s\n", f.Verdict)
	if f.Snippet != "" {
		fmt.Fprintf(w, "    snippet: %s\n", f.Snippet)
	}
	fmt.Fprintln(w)
}

func formatSeverity(severity string, color bool) string {
	if !color {
		return severity
	}
	c := colorFor(severity)
	if c == "" {
		return severity
	}
	return c + severity + ansiReset
}

// printSummary writes the run accounting to stderr. It deliberately goes to
// stderr so -json stdout stays machine-parseable.
func printSummary(w io.Writer, tasks int, requests int64, minSeverity string, reported, suppressed map[string]int) {
	var parts []string
	for _, sev := range []string{"high", "medium", "low", "info"} {
		if n := reported[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	for _, sev := range []string{"high", "medium", "low", "info"} {
		if n := suppressed[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s suppressed", n, sev))
		}
	}
	detail := "no findings at or above " + minSeverity
	if len(parts) > 0 {
		detail = strings.Join(parts, ", ")
	}
	fmt.Fprintf(w, "kxss-ctx: scanned %d task(s), %d request(s): %s\n", tasks, requests, detail)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
