package main

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeParamEndToEnd(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("x")
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/redir":
			w.Header().Set("Location", "/landing?next="+v)
			w.WriteHeader(http.StatusFound)
		case "/attr":
			// Raw reflection inside a double-quoted attribute.
			fmt.Fprintf(w, `<input value="%s">`, v)
		case "/attr-enc":
			// Fully HTML-escaped by the templating engine.
			fmt.Fprintf(w, `<input value="%s">`, html.EscapeString(v))
		case "/attr-mixed":
			fmt.Fprintf(w, `<input value="%s">`, strings.ReplaceAll(html.EscapeString(v), "&lt;", "<"))
		case "/text":
			// Angle brackets stripped: nothing can break out of text.
			fmt.Fprintf(w, `<div>%s</div>`, strings.ReplaceAll(v, "<", ""))
		case "/uq":
			// Unquoted attribute whose whole value is the reflection.
			fmt.Fprintf(w, `<input value=%s>`, v)
		case "/script":
			fmt.Fprintf(w, `<script>var x = "%s";</script>`, v)
		case "/json":
			fmt.Fprintf(w, `<script type="application/json">{"k":"%s"}</script>`, v)
		case "/csp":
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'nonce-abc'")
			fmt.Fprintf(w, `<input value="%s">`, v)
		}
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := newClient(fetchOpts{Timeout: 5 * time.Second})
	o := fetchOpts{Timeout: 5 * time.Second}
	lim := newLimiter(0)

	run := func(path string) []finding {
		t.Helper()
		f, err := analyzeParam(client, o, srv.URL+path+"?x=1", "x", lim, 3)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return f
	}

	// 1) raw reflection in a double-quoted attribute -> high
	f := run("/attr")
	if len(f) != 1 || f[0].Kind != "attr-double-quoted" || f[0].Severity != "high" {
		t.Fatalf("raw attr: %+v", f)
	}
	if !strings.Contains(f[0].Verdict, "literal") || f[0].PoC == "" {
		t.Errorf("raw attr verdict/poc: %q / %q", f[0].Verdict, f[0].PoC)
	}

	// 2) encoded quote and angle bracket in dq attribute -> info
	f = run("/attr-enc")
	if len(f) != 1 || f[0].Severity != "info" || !strings.Contains(f[0].Verdict, "encoded") {
		t.Fatalf("encoded attr: %+v", f)
	}
	if f[0].PoC != "" {
		t.Errorf("encoded attr should not carry a PoC, got %q", f[0].PoC)
	}

	// 2b) quote encoded but "<" literal in a double-quoted attribute: the
	// quote is the only terminator, so this is a reflection, not a breakout.
	f = run("/attr-mixed")
	if len(f) != 1 || f[0].Severity != "info" || !strings.Contains(f[0].Verdict, "not exploitable") {
		t.Fatalf("mixed attr: %+v", f)
	}
	if f[0].PoC != "" {
		t.Errorf("mixed attr must not carry a PoC, got %q", f[0].PoC)
	}

	// 3) text context with < stripped -> info, PoC withheld
	f = run("/text")
	if len(f) != 1 || f[0].Kind != "html-text" || f[0].Severity != "info" {
		t.Fatalf("text: %+v", f)
	}
	if f[0].PoC != "" {
		t.Errorf("text info finding should not carry a PoC, got %q", f[0].PoC)
	}

	// 4) unquoted attr where the marker is the whole value -> corrected context
	f = run("/uq")
	if len(f) != 1 || f[0].Kind != "attr-unquoted" || f[0].Tag != "input" || f[0].Attr != "value" {
		t.Fatalf("unquoted: %+v", f)
	}

	// 5) JS double-quoted string -> high with matching PoC
	f = run("/script")
	if len(f) != 1 || f[0].Kind != "script-double-quoted" || f[0].Severity != "high" {
		t.Fatalf("script: %+v", f)
	}
	if f[0].PoC != "\";alert(document.domain);//" {
		t.Errorf("script poc = %q", f[0].PoC)
	}

	// 6) JSON script block: quote must NOT be probed as a JS breakout
	f = run("/json")
	if len(f) != 1 || f[0].ScriptType != "application/json" || f[0].Kind != "script-double-quoted" {
		t.Fatalf("json: %+v", f)
	}
	for _, p := range f[0].Chars {
		if p.Char == `"` {
			t.Errorf("json script block probed a JS quote: %+v", f[0].Chars)
		}
	}

	// 7) CSP with nonce -> verdict warns that inline may be blocked
	f = run("/csp")
	if len(f) != 1 || !strings.Contains(f[0].Verdict, "CSP present") {
		t.Fatalf("csp: %+v", f)
	}

	// 8) relative redirect reflection -> info: a same-origin bounce is not an
	// open redirect. Only a cross-origin Location is reported as high.
	rf, err := analyzeParam(client, o, srv.URL+"/redir?x=1", "x", lim, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(rf) != 1 || rf[0].Kind != "redirect-location" || rf[0].Severity != "info" {
		t.Fatalf("redirect: %+v", rf)
	}
	if rf[0].PoC != "" {
		t.Errorf("relative redirect should not carry a PoC, got %q", rf[0].PoC)
	}
}

func TestAnalyzeParamConcurrent(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("x")
		fmt.Fprintf(w, `<input value="%s"><div>%s</div>`, v, v)
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := newClient(fetchOpts{Timeout: 5 * time.Second})
	o := fetchOpts{Timeout: 5 * time.Second}
	lim := newLimiter(0)

	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			_, err := analyzeParam(client, o, srv.URL+"/?x=1", "x", lim, 2)
			done <- err
		}()
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent analyzeParam: %v", err)
		}
	}
}
