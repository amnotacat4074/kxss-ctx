package main

// Content-Security-Policy inspection. The goal is narrow: tell an operator
// whether a CSP is present and whether it is likely to block inline event
// handlers, because that changes the practical impact of a confirmed
// reflection. This is not a policy validator.

import (
	"html"
	"net/http"
	"regexp"
	"strings"
)

// cspInfo is a parsed Content-Security-Policy.
type cspInfo struct {
	Present    bool
	Raw        string
	Directives map[string]string

	// policies holds every policy that applies. Multiple CSP headers are
	// enforced as an intersection, so AllowsInline must consult all of them.
	policies []map[string]string
}

var (
	metaTagRe     = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	httpEquivRe   = regexp.MustCompile(`(?is)\bhttp-equiv\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))`)
	contentAttrRe = regexp.MustCompile(`(?is)\bcontent\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))`)
)

// parseCSP reads the CSP from response headers, falling back to a
// <meta http-equiv="Content-Security-Policy"> element in the document.
func parseCSP(h http.Header, body []byte) cspInfo {
	info := cspInfo{Directives: map[string]string{}}

	var raws []string
	for _, name := range []string{"Content-Security-Policy", "X-Content-Security-Policy"} {
		for _, v := range h.Values(name) {
			if strings.TrimSpace(v) != "" {
				raws = append(raws, v)
			}
		}
	}
	if len(raws) == 0 && len(body) > 0 {
		// A meta policy only applies when it is in the document head; the
		// first 256 KiB is more than enough to cover that.
		head := body
		if len(head) > 256<<10 {
			head = head[:256<<10]
		}
		if v := metaCSP(head); v != "" {
			raws = append(raws, v)
		}
	}
	if len(raws) == 0 {
		return info
	}

	info.Present = true
	info.Raw = strings.Join(raws, " , ")
	for _, raw := range raws {
		pol := parseDirectives(raw)
		info.policies = append(info.policies, pol)
		for k, v := range pol {
			info.Directives[k] = v
		}
	}
	return info
}

func parseDirectives(raw string) map[string]string {
	pol := make(map[string]string)
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val := part, ""
		if i := strings.IndexAny(part, " \t"); i >= 0 {
			name, val = part[:i], strings.TrimSpace(part[i+1:])
		}
		pol[strings.ToLower(name)] = val
	}
	return pol
}

// metaCSP extracts the first CSP meta policy from body.
func metaCSP(body []byte) string {
	for _, tag := range metaTagRe.FindAll(body, 16) {
		he := httpEquivRe.FindSubmatch(tag)
		if he == nil || !strings.EqualFold(strings.TrimSpace(attrValue(he)), "content-security-policy") {
			continue
		}
		cm := contentAttrRe.FindSubmatch(tag)
		if cm == nil {
			continue
		}
		v := html.UnescapeString(strings.TrimSpace(attrValue(cm)))
		if v != "" {
			return v
		}
	}
	return ""
}

// attrValue returns the first non-empty quoted/unquoted capture from an
// attribute regex match.
func attrValue(m [][]byte) string {
	for _, g := range m[2:] {
		if len(g) > 0 {
			return string(g)
		}
	}
	return ""
}

// AllowsInline reports whether inline scripts and event handlers are likely to
// run. No CSP, no script-src/default-src restriction, or an allowing directive
// all return true. A nonce or hash in script-src causes 'unsafe-inline' to be
// ignored, as browsers do.
func (c cspInfo) AllowsInline() bool {
	if !c.Present {
		return true
	}
	if len(c.policies) == 0 {
		return directiveAllowsInline(c.Directives)
	}
	for _, pol := range c.policies {
		if !directiveAllowsInline(pol) {
			return false
		}
	}
	return true
}

func directiveAllowsInline(pol map[string]string) bool {
	val, ok := pol["script-src"]
	if !ok {
		if val, ok = pol["script-src-elem"]; !ok {
			val, ok = pol["default-src"]
		}
	}
	if !ok {
		// Nothing restricts scripts, so inline is allowed.
		return true
	}
	allows, nonceOrHash := false, false
	for _, tok := range strings.Fields(val) {
		switch {
		case tok == "'unsafe-inline'" || tok == "unsafe-inline" || tok == "*":
			allows = true
		case strings.HasPrefix(tok, "'nonce-"), strings.HasPrefix(tok, "'sha256-"),
			strings.HasPrefix(tok, "'sha384-"), strings.HasPrefix(tok, "'sha512-"):
			nonceOrHash = true
		}
	}
	return allows && !nonceOrHash
}

// Summary returns a single-line, truncated rendering of the policy.
func (c cspInfo) Summary() string {
	if !c.Present {
		return ""
	}
	s := strings.Join(strings.Fields(c.Raw), " ")
	if len(s) > 180 {
		s = s[:177] + "..."
	}
	return s
}
