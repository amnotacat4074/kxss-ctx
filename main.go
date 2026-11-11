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
	"time"
)

// defaultUA is the User-Agent sent when -ua is not given. Tools that send a
// browser UA (as kxss does) lie about what is on the wire; this advertises the
// tool so a defender can identify the traffic.
const defaultUA = "kxss-ctx/1.0 (context-aware XSS reflection scanner; +https://github.com/amnotacat4074/kxss-ctx)"

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
		single   string
		file     string
		jsonOut  bool
		conc     int
		rate     float64
		timeout  time.Duration
		follow   bool
		insecure bool
		ua       string
		cookie   string
		maxOcc   int
		verbose  bool
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
	flag.Var(headers, "H", "extra request header 'Name: value' (repeatable)")
	flag.Parse()

	urls, err := readURLs(single, file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kxss-ctx: %v\n", err)
		os.Exit(2)
	}
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "kxss-ctx: no URLs supplied (use -u, -f or stdin)")
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
	for f := range results {
		if jsonOut {
			all = append(all, f)
			continue
		}
		printFinding(os.Stdout, f)
	}

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

func printFinding(w io.Writer, f finding) {
	fmt.Fprintf(w, "[%s] %s  param=%q context=%s", f.Severity, f.URL, f.Param, f.Kind)
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

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
