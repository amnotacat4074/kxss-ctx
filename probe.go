package main

// HTTP plumbing: client construction, a single request, URL/parameter
// manipulation and a shared request-rate limiter.
//
// Standard library only. The one deliberate default is Follow=false: a
// scanner acting under an authorisation must not silently follow redirects
// onto hosts outside scope.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// maxBodyBytes bounds how much of a response body is read.
const maxBodyBytes = 8 << 20

// fetchOpts is the per-run request configuration.
type fetchOpts struct {
	UA       string        // User-Agent; defaultUA when empty
	Cookie   string        // raw Cookie header value, if any
	Headers  http.Header   // extra request headers (Host handled specially)
	Timeout  time.Duration // per-request timeout
	Follow   bool          // follow redirects (default false)
	Insecure bool          // skip TLS verification
	Method   string        // HTTP method; GET when empty
}

// fetchResult is one response, already read and closed.
type fetchResult struct {
	Status           int
	Header           http.Header
	Body             []byte
	Location         string // raw Location header, if any
	ResolvedLocation string // Location resolved against the request URL
	URL              string // URL that produced this response
}

// newClient builds an *http.Client honouring o.
func newClient(o fetchOpts) *http.Client {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: o.Insecure}, //nolint:gosec // explicit -k opt-in
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	c := &http.Client{Transport: tr, Timeout: timeout}
	if !o.Follow {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			// Returning ErrUseLastResponse hands the 3xx back to the caller,
			// which is what the Location-reflection check wants.
			return http.ErrUseLastResponse
		}
	}
	return c
}

// fetch performs one request and reads the (bounded) body.
func fetch(client *http.Client, o fetchOpts, rawurl string) (*fetchResult, error) {
	if client == nil {
		return nil, errors.New("nil http client")
	}
	method := o.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequest(method, rawurl, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	ua := o.UA
	if ua == "" {
		ua = defaultUA
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	if o.Cookie != "" {
		req.Header.Set("Cookie", o.Cookie)
	}
	for name, values := range o.Headers {
		for _, v := range values {
			if strings.EqualFold(name, "Host") {
				// net/http ignores a Host header set through Header.
				req.Host = v
				continue
			}
			req.Header.Add(name, v)
		}
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	out := &fetchResult{
		Status:   res.StatusCode,
		Header:   res.Header.Clone(),
		Body:     body,
		Location: res.Header.Get("Location"),
		URL:      rawurl,
	}
	if res.Request != nil && res.Request.URL != nil {
		out.URL = res.Request.URL.String()
	}
	if out.Location != "" {
		if base, perr := url.Parse(rawurl); perr == nil {
			if ref, lerr := base.Parse(out.Location); lerr == nil {
				out.ResolvedLocation = ref.String()
			}
		}
	}
	return out, nil
}

// normalizeURL adds a scheme when the operator typed a bare host.
func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	if strings.HasPrefix(raw, "//") {
		return "https:" + raw
	}
	if !strings.Contains(raw, "://") {
		return "https://" + raw
	}
	return raw
}

// setParam returns rawurl with query parameter param set to value. Existing
// parameters and the fragment are preserved.
func setParam(rawurl, param, value string) (string, error) {
	if param == "" {
		return "", errors.New("empty parameter name")
	}
	u, err := url.Parse(normalizeURL(rawurl))
	if err != nil {
		return "", fmt.Errorf("parsing URL: %w", err)
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// urlParams lists the query parameter names present in rawurl, in document
// order, de-duplicated.
func urlParams(rawurl string) ([]string, error) {
	u, err := url.Parse(normalizeURL(rawurl))
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}
	if u.RawQuery == "" {
		return nil, nil
	}
	var out []string
	seen := make(map[string]bool)
	for _, pair := range strings.Split(u.RawQuery, "&") {
		if pair == "" {
			continue
		}
		name := pair
		if i := strings.IndexByte(pair, '='); i >= 0 {
			name = pair[:i]
		}
		name, err = url.QueryUnescape(name)
		if err != nil {
			return nil, fmt.Errorf("parsing query parameter name %q: %w", name, err)
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out, nil
}

// limiter spaces requests at a fixed interval across all workers. It reserves
// a slot under a short lock and then sleeps outside it, so concurrent workers
// never serialise on the sleep itself.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// newLimiter returns a limiter for rps requests per second. rps <= 0 disables
// rate limiting (wait is a no-op).
func newLimiter(rps float64) *limiter {
	if rps <= 0 {
		return &limiter{}
	}
	return &limiter{interval: time.Duration(float64(time.Second) / rps)}
}

// wait blocks until this caller's reserved slot.
func (l *limiter) wait() {
	if l == nil || l.interval <= 0 {
		return
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	slot := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()
	if d := time.Until(slot); d > 0 {
		time.Sleep(d)
	}
}
