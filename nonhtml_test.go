package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A response served as JavaScript is not an HTML document. Injecting "<svg
// onload=...>" into it does not create markup, so a literal "<" must not be
// reported as reflected XSS. This is the shape that kxss flags on tracking
// endpoints (e.g. var <value>={"ec":"nc"};) and it must stay quiet here.
func TestNonHTMLResponseIsNotHTMLContext(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `var %s={"ec":"nc"};`, r.URL.Query().Get("var"))
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"var":"%s"}`, r.URL.Query().Get("var"))
		case "/plain":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, r.URL.Query().Get("var"))
		}
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := newClient(fetchOpts{Timeout: 5 * time.Second})
	o := fetchOpts{Timeout: 5 * time.Second}

	for _, path := range []string{"/js", "/json", "/plain"} {
		fs, err := analyzeParam(client, o, srv.URL+path+"?var=1", "var", newLimiter(0), 3)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if len(fs) == 0 {
			t.Fatalf("%s: expected an informational finding, got none", path)
		}
		for _, f := range fs {
			if f.Severity == "high" || f.Severity == "medium" {
				t.Errorf("%s: non-HTML response reported as %s: %+v", path, f.Severity, f)
			}
			if f.Kind != "non-html" {
				t.Errorf("%s: expected context 'non-html', got %q", path, f.Kind)
			}
			if f.PoC != "" {
				t.Errorf("%s: non-HTML finding must not carry a PoC, got %q", path, f.PoC)
			}
		}
	}
}

// The gate must not suppress real HTML documents.
func TestHTMLResponseStillFires(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<div>%s</div>`, r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	client := newClient(fetchOpts{Timeout: 5 * time.Second})
	o := fetchOpts{Timeout: 5 * time.Second}
	fs, err := analyzeParam(client, o, srv.URL+"/?q=1", "q", newLimiter(0), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Severity != "high" {
		t.Fatalf("HTML document should still be reported high: %+v", fs)
	}
}
