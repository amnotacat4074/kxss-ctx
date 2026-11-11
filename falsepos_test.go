package main

// False-positive regression corpus.
//
// Every negative endpoint below reflects the probe value verbatim in some
// form, but neutralises the bytes that would actually end the surrounding
// syntactic context. A scanner that reports "high" (or "medium") for any of
// them has produced the classic "it reflected, therefore it is XSS" false
// positive that kxss-ctx exists to avoid.
//
// The positive endpoints pin the other side of the trade-off: the hardened
// classification must not go quiet on a genuine breakout.

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// jsonScriptEscape mirrors what a serializer such as Go's encoding/json (with
// HTML escaping on) or a hardened JSON.stringify wrapper emits inside a
// <script type="application/json"> block: the bytes that can end the script
// element or start a tag become \uXXXX, while quotes and backslashes stay
// legal JSON.
func jsonScriptEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '<':
			b.WriteString(`\u003c`)
		case '>':
			b.WriteString(`\u003e`)
		case '&':
			b.WriteString(`\u0026`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// falsePositiveServer serves the regression corpus. Each handler reflects the
// x parameter, optionally after the kind of escaping/filtering that a real
// framework applies.
func falsePositiveServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("x")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/next":
			// Next.js-style __NEXT_DATA__: JSON with <, >, & escaped.
			fmt.Fprintf(w, `<script type="application/json">{"s":"%s"}</script>`, jsonScriptEscape(v))
		case "/adpx":
			// Third-party pixel tag: the value is URL-encoded inside a
			// double-quoted src attribute.
			enc := strings.ReplaceAll(v, `"`, "%22")
			enc = strings.ReplaceAll(enc, "<", "%3C")
			fmt.Fprintf(w, `<img src="https://ads.example/px?u=%s">`, enc)
		case "/escaped":
			// Templating engine with HTML escaping, in text context.
			fmt.Fprintf(w, `<div>%s</div>`, html.EscapeString(v))
		case "/noreflect":
			// The value never reaches the response.
			fmt.Fprint(w, `<div>static content</div>`)
		case "/comment":
			// '-' stripped: the comment can never be closed.
			fmt.Fprintf(w, `<!-- %s -->`, strings.ReplaceAll(v, "-", ""))
		case "/style":
			// '/' stripped: "</style" can never be formed.
			fmt.Fprintf(w, `<style>%s</style>`, strings.ReplaceAll(v, "/", ""))
		case "/title":
			// RCDATA element, same '/' stripping.
			fmt.Fprintf(w, `<title>%s</title>`, strings.ReplaceAll(v, "/", ""))
		case "/json-lt-escaped":
			// Only '<' is escaped, mirroring observed __NEXT_DATA__ output:
			// a lone '<' cannot open a tag, and the JSON string is inert.
			fmt.Fprintf(w, `<script type="application/json">{"s":"%s"}</script>`, strings.ReplaceAll(v, "<", `\u003c`))
		case "/waf":
			// An edge WAF blocks the request but echoes the value in an
			// error page, with '<' stripped. A 403 is not a reflection.
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `<div>blocked: %s</div>`, strings.ReplaceAll(v, "<", ""))
		case "/raw-text":
			// TRUE POSITIVE: raw reflection in HTML text.
			fmt.Fprintf(w, `<div>%s</div>`, v)
		case "/raw-attr":
			// TRUE POSITIVE: raw reflection in a double-quoted attribute.
			fmt.Fprintf(w, `<input value="%s">`, v)
		case "/cross-redirect":
			// TRUE POSITIVE: the value becomes the redirect HOST.
			w.Header().Set("Location", "https://"+v+".evil.example/")
			w.WriteHeader(http.StatusFound)
		case "/fixed-host-redirect":
			// Cross-host but server-fixed destination: the value only lands in
			// a query parameter, exactly like the AT&T ISAM kickoff endpoint.
			w.Header().Set("Location", "https://oidc.example/kickoff?alt_dest="+v)
			w.WriteHeader(http.StatusFound)
		case "/same-redirect":
			// Same-origin / relative bounce: routine, not an open redirect.
			w.Header().Set("Location", "/landing?n="+v)
			w.WriteHeader(http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
}

// worstSeverity returns the most severe severity in fs, "" when empty.
func worstSeverity(fs []finding) string {
	rank := map[string]int{"": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
	worst := ""
	for _, f := range fs {
		if rank[f.Severity] > rank[worst] {
			worst = f.Severity
		}
	}
	return worst
}

func TestFalsePositiveCorpus(t *testing.T) {
	srv := falsePositiveServer()
	defer srv.Close()

	client := newClient(fetchOpts{Timeout: 5 * time.Second})
	o := fetchOpts{Timeout: 5 * time.Second}
	lim := newLimiter(0)

	cases := []struct {
		path string
		want string // "<=info", "none" or an exact severity
	}{
		// Negatives: reflected, but not exploitable in that context.
		{"/next", "<=info"},
		{"/adpx", "<=info"},
		{"/escaped", "<=info"},
		{"/comment", "<=info"},
		{"/style", "<=info"},
		{"/title", "<=info"},
		{"/json-lt-escaped", "<=info"},
		{"/waf", "<=info"},
		{"/noreflect", "none"},
		// Positives: the harded classification must still fire.
		{"/raw-text", "high"},
		{"/raw-attr", "high"},
		{"/cross-redirect", "high"},
		{"/fixed-host-redirect", "info"},
		{"/same-redirect", "info"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(strings.TrimPrefix(tc.path, "/"), func(t *testing.T) {
			f, err := analyzeParam(client, o, srv.URL+tc.path+"?x=1", "x", lim, 3)
			if err != nil {
				t.Fatalf("%s: %v", tc.path, err)
			}
			worst := worstSeverity(f)
			switch tc.want {
			case "none":
				if len(f) != 0 {
					t.Fatalf("expected zero findings, got %d: %+v", len(f), f)
				}
			case "<=info":
				if len(f) == 0 {
					t.Fatalf("expected the reflection to be classified, got no findings")
				}
				if worst == "high" || worst == "medium" {
					t.Fatalf("worst severity = %q, want info or lower: %+v", worst, f)
				}
			default:
				if worst != tc.want {
					t.Fatalf("worst severity = %q, want %q: %+v", worst, tc.want, f)
				}
			}

			// A PoC is only ever a claim of demonstrated breakout (high) or an
			// explicitly unverified scheme-control candidate (low). Anything
			// else carrying a PoC is how false positives get reported.
			for _, fd := range f {
				if fd.PoC != "" && fd.Severity != "high" && fd.Severity != "low" {
					t.Errorf("severity %q carries PoC %q; only high/low findings may carry a PoC", fd.Severity, fd.PoC)
				}
			}
		})
	}
}
