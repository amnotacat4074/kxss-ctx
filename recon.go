package main

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// runRecon builds a scoped candidate URL list for a domain:
//
//	subfinder + assetfinder -> subs.txt
//	httpx                   -> live.txt
//	katana + gau            -> urls.txt
//	uro                     -> urls_clean.txt
//	query-string URLs only  -> params.txt
//	scope filter            -> []string returned (and written back to params.txt)
//
// Every stage is skippable: a missing tool is logged and the pipeline degrades
// instead of failing. Results are cached on disk, so -reuse resumes.
func runRecon(domain, dir string, reuse, verbose bool) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	logf := func(msg string) { fmt.Fprintln(os.Stderr, "kxss-ctx: recon: "+msg) }

	subs := filepath.Join(dir, "subs.txt")
	live := filepath.Join(dir, "live.txt")
	urlsFile := filepath.Join(dir, "urls.txt")
	clean := filepath.Join(dir, "urls_clean.txt")
	params := filepath.Join(dir, "params.txt")

	stage := func(name, out string, fn func() error) error {
		if reuse && fileSize(out) > 0 {
			logf(name + ": reusing " + out + " (" + itoa(countLines(out)) + " lines)")
			return nil
		}
		logf(name + ": running")
		if err := fn(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		logf(name + ": " + itoa(countLines(out)) + " lines -> " + out)
		return nil
	}

	// 1. Subdomains.
	if err := stage("subdomains", subs, func() error {
		_ = os.Remove(subs)
		ran := false
		if have("subfinder") {
			if err := appendCmd(subs, "subfinder", "-all", "-silent", "-d", domain); err != nil {
				logf("subfinder failed: " + err.Error())
			} else {
				ran = true
			}
		} else {
			logf("subfinder not installed - skipped")
		}
		if have("assetfinder") {
			if err := appendCmd(subs, "assetfinder", "--subs-only", domain); err != nil {
				logf("assetfinder failed: " + err.Error())
			} else {
				ran = true
			}
		} else {
			logf("assetfinder not installed - skipped")
		}
		if !ran {
			logf("no subdomain tool available - falling back to " + domain)
			if err := writeLines(subs, []string{domain}); err != nil {
				return err
			}
		}
		return dedupeFile(subs)
	}); err != nil {
		return nil, err
	}

	// 2. Live HTTP hosts.
	if err := stage("httpx", live, func() error {
		if !have("httpx") {
			logf("httpx not installed - using the raw subdomain list")
			return copyFile(subs, live)
		}
		return feedCmd(subs, live, "httpx", "-silent", "-threads", "50", "-rate-limit", "150", "-timeout", "10")
	}); err != nil {
		return nil, err
	}

	// 3. Crawled + archived URLs.
	if err := stage("katana+gau", urlsFile, func() error {
		_ = os.Remove(urlsFile)
		if have("katana") {
			if err := feedCmd(live, urlsFile, "katana", "-silent", "-jc", "-d", "5"); err != nil {
				logf("katana failed: " + err.Error())
			}
		} else {
			logf("katana not installed - skipped")
		}
		if have("gau") {
			if err := feedCmd(subs, urlsFile, "gau", "--threads", "50", "--providers", "wayback,otx,urlscan,commoncrawl"); err != nil {
				logf("gau failed: " + err.Error())
			}
		} else {
			logf("gau not installed - skipped")
		}
		return dedupeFile(urlsFile)
	}); err != nil {
		return nil, err
	}

	// 4. Normalise.
	if err := stage("uro", clean, func() error {
		if !have("uro") {
			logf("uro not installed - copying instead")
			return copyFile(urlsFile, clean)
		}
		return feedCmd(urlsFile, clean, "uro")
	}); err != nil {
		return nil, err
	}

	// 5. Only URLs that carry a query string - anything else has no
	//    reflection surface to test.
	if err := stage("params", params, func() error {
		return filterQueryURLs(clean, params)
	}); err != nil {
		return nil, err
	}

	all, err := readLines(params)
	if err != nil {
		return nil, err
	}
	inScope := filterScope(all, domain)
	if dropped := len(all) - len(inScope); dropped > 0 {
		logf("scope filter: dropped " + itoa(dropped) + " URL(s) outside " + domain)
	}
	if err := writeLines(params, inScope); err != nil {
		return nil, err
	}
	logf("ready: " + itoa(len(inScope)) + " in-scope URL(s) with parameters in " + params)
	return inScope, nil
}

func have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// feedCmd runs name with args, piping inFile to stdin and capturing stdout.
func feedCmd(inFile, outFile, name string, args ...string) error {
	in, err := os.Open(inFile)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer out.Close()
	cmd := exec.Command(name, args...)
	cmd.Stdin = in
	cmd.Stdout = out
	return cmd.Run()
}

// appendCmd appends a tool's stdout to outFile.
func appendCmd(outFile, name string, args ...string) error {
	out, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	cmd := exec.Command(name, args...)
	cmd.Stdout = out
	return cmd.Run()
}

func dedupeFile(path string) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(lines))
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	sort.Strings(out)
	return writeLines(path, out)
}

func filterQueryURLs(inFile, outFile string) error {
	lines, err := readLines(inFile)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(lines))
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if !strings.Contains(l, "?") || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	sort.Strings(out)
	return writeLines(outFile, out)
}

// filterScope keeps only URLs whose host is domain or a subdomain of it. This
// is what stops a recon run from spraying third-party infrastructure (CDNs,
// ad trackers, analytics) that showed up in crawl or archive results.
func filterScope(urls []string, domain string) []string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	out := make([]string, 0, len(urls))
	for _, raw := range urls {
		u := strings.TrimSpace(raw)
		if u == "" {
			continue
		}
		h := hostOf(u)
		if h == "" {
			continue
		}
		h = strings.ToLower(h)
		if h == domain || strings.HasSuffix(h, "."+domain) {
			out = append(out, u)
		}
	}
	return out
}

func hostOf(raw string) string {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			return err
		}
	}
	return nil
}

func countLines(path string) int {
	lines, err := readLines(path)
	if err != nil {
		return 0
	}
	return len(lines)
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
