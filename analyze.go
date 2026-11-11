package main

// Core analysis: reflect a unique marker through one query parameter, locate
// every reflection in the response, classify its syntactic context, then probe
// the characters that would break out of that context.
//
// The design goal is to avoid the classic "reflected, therefore XSS" claim. A
// reflection is only reported as a finding once the characters that end the
// current context are observed to survive verbatim in the response.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// charProbe records the result of sending one dangerous character.
type charProbe struct {
	Char     string `json:"char"`
	Literal  bool   `json:"literal"`
	Encoding string `json:"encoding,omitempty"`
	Sample   string `json:"sample,omitempty"`
}

// finding is one reflection site.
type finding struct {
	URL        string      `json:"url"`
	RequestURL string      `json:"request_url"`
	Param      string      `json:"param"`
	Kind       string      `json:"context"`
	Tag        string      `json:"tag,omitempty"`
	Attr       string      `json:"attr,omitempty"`
	ScriptType string      `json:"script_type,omitempty"`
	Offset     int         `json:"offset"`
	Snippet    string      `json:"snippet"`
	Chars      []charProbe `json:"chars,omitempty"`
	Severity   string      `json:"severity"`
	Verdict    string      `json:"verdict"`
	PoC        string      `json:"poc,omitempty"`
	CSP        string      `json:"csp,omitempty"`
	Status     int         `json:"status"`
	Note       string      `json:"note,omitempty"`
}

// analyzeParam tests one (url, parameter) pair.
func analyzeParam(client *http.Client, o fetchOpts, rawurl, param string, lim *limiter, maxOcc int) ([]finding, error) {
	if maxOcc <= 0 {
		maxOcc = 3
	}
	marker := newMarker()
	target, err := setParam(rawurl, param, marker)
	if err != nil {
		return nil, fmt.Errorf("building request URL: %w", err)
	}

	lim.wait()
	res, err := fetch(client, o, target)
	if err != nil {
		return nil, err
	}
	csp := parseCSP(res.Header, res.Body)
	base := finding{
		URL:        rawurl,
		RequestURL: target,
		Param:      param,
		Status:     res.Status,
		CSP:        csp.Summary(),
	}
	var out []finding

	// 1. Reflection into a redirect target.
	if res.Location != "" && strings.Contains(res.Location, marker) {
		f := base
		f.Kind = "redirect-location"
		f.Severity = "medium"
		f.Verdict = "parameter reflected into Location header (open-redirect candidate)"
		f.Offset = strings.Index(res.Location, marker)
		f.Snippet = snippetAround([]byte(res.Location), f.Offset, len(marker))
		f.PoC = strings.ReplaceAll(res.Location, marker, "https://attacker.example/")
		f.Note = "reflection in Location only; a non-relative attacker URL was not requested. Verify manually before reporting."
		out = append(out, f)
	} else if res.URL != target && strings.Contains(res.URL, marker) {
		f := base
		f.Kind = "redirect-location"
		f.Severity = "medium"
		f.Verdict = "parameter reflected into the URL after following redirects (open-redirect candidate)"
		f.Offset = strings.Index(res.URL, marker)
		f.Snippet = snippetAround([]byte(res.URL), f.Offset, len(marker))
		f.PoC = strings.ReplaceAll(res.URL, marker, "https://attacker.example/")
		f.Note = "redirects were followed (-follow); verify the final hop manually."
		out = append(out, f)
	}

	// 2. Reflections in the body.
	body := res.Body
	indexes := indexAll(body, []byte(marker))
	if len(indexes) > maxOcc {
		indexes = indexes[:maxOcc]
	}
	for occ, idx := range indexes {
		ctx := contextAt(body, idx)
		if ctx.Tag != "script" {
			// scan.go records the last type= value for any tag; only a
			// script's type matters to a reader.
			ctx.ScriptType = ""
		}
		atStart := idx == ctx.ValueStart
		f := base
		f.Offset = idx
		f.Kind = ctx.Kind.String()
		f.Tag = ctx.Tag
		f.Attr = ctx.Attr
		f.ScriptType = ctx.ScriptType
		f.Snippet = snippetAround(body, idx, len(marker))

		chars := dangerousFor(ctx, atStart)
		if ctx.Tag == "script" && !isJSScript(ctx.ScriptType) {
			// JSON / template script blocks are data: only closing the tag
			// can escape them, regardless of JS quoting state.
			chars = []byte{'<'}
		}
		if len(chars) == 0 {
			f.Severity = "info"
			f.Verdict = fmt.Sprintf("reflection in %s context has no breakout characters to test", f.Kind)
			if ctx.Kind == KindTag {
				f.Note = "reflection sits in tag syntax (not inside an attribute value); this position is not probed - review manually."
			}
			out = append(out, f)
			continue
		}

		probes := make([]charProbe, 0, len(chars))
		for _, ch := range chars {
			p, perr := probeChar(client, o, rawurl, param, marker, ch, occ, lim)
			if perr != nil {
				if f.Note == "" {
					f.Note = "probe error: " + perr.Error()
				} else {
					f.Note += "; probe error: " + perr.Error()
				}
				continue
			}
			probes = append(probes, p)
		}
		f.Chars = probes
		f.Severity, f.Verdict, f.PoC = assess(ctx, probes, csp, atStart)
		out = append(out, f)
	}
	return out, nil
}

// probeChar sends marker+ch and reports whether ch survives verbatim,
// survives encoded, or is transformed away. occ selects which reflection to
// inspect, so multiple reflections in one document are probed in place.
func probeChar(client *http.Client, o fetchOpts, rawurl, param, marker string, ch byte, occ int, lim *limiter) (charProbe, error) {
	p := charProbe{Char: string([]byte{ch})}
	// A random suffix follows the probed character so that a "literal" match
	// can only come from the reflected value, never from the static HTML that
	// happens to follow the reflection (e.g. a stripped "<" followed by
	// "</div>"). It also makes an encoded match position-anchored.
	suffix := "zq" + randHex(4)
	payload := marker + string([]byte{ch}) + suffix
	target, err := setParam(rawurl, param, payload)
	if err != nil {
		return p, err
	}
	lim.wait()
	res, err := fetch(client, o, target)
	if err != nil {
		return p, err
	}
	indexes := indexAll(res.Body, []byte(marker))
	if len(indexes) == 0 {
		p.Encoding = "not-reflected"
		return p, nil
	}
	idx := indexes[0]
	if occ >= 0 && occ < len(indexes) {
		idx = indexes[occ]
	}
	after := res.Body[idx+len(marker):]
	p.Sample = probeSample(after)

	if len(after) > 1 && after[0] == ch && bytes.HasPrefix(after[1:], []byte(suffix)) {
		p.Literal = true
		p.Sample = ""
		return p, nil
	}
	if match, decoded, n := detectEncodingAt(after); match != "" && decoded == string([]byte{ch}) && bytes.HasPrefix(after[n:], []byte(suffix)) {
		p.Encoding = match
		return p, nil
	}
	p.Encoding = "transformed"
	return p, nil
}

// dangerousFor returns the characters worth probing in context c. atStart is
// true when the reflection begins exactly at the start of the attribute value
// (or other value region), which matters for URL-valued attributes.
func dangerousFor(c Context, atStart bool) []byte {
	var out []byte
	switch c.Kind {
	case KindText, KindRcdata, KindScriptRaw, KindStyle:
		out = []byte{'<'}
	case KindAttrDQ:
		out = []byte{'"', '<'}
	case KindAttrSQ:
		out = []byte{'\'', '<'}
	case KindAttrUQ:
		out = []byte{' ', '>', '"', '\'', '`', '=', '<'}
	case KindScriptDQ:
		out = []byte{'"', '<'}
	case KindScriptSQ:
		out = []byte{'\'', '<'}
	case KindScriptTemplate:
		out = []byte{'`', '$', '<'}
	case KindComment:
		out = []byte{'>', '-'}
	case KindTag:
		return nil
	default:
		return nil
	}
	if isURLAttr(c.Attr) && atStart && isAttrValueKind(c.Kind) {
		out = append(out, ':', '/')
	}
	return out
}

// isAttrValueKind reports whether the context is an attribute value, i.e. a
// position where a URL-valued attribute's scheme still matters.
func isAttrValueKind(k Kind) bool {
	return k == KindAttrDQ || k == KindAttrSQ || k == KindAttrUQ
}

// assess turns probe results into a severity, a human verdict and a candidate
// PoC. A finding is only "high" when at least one character that ends the
// context survived verbatim.
func assess(c Context, probes []charProbe, csp cspInfo, atStart bool) (severity, verdict, poc string) {
	var literal, encoded, missing, transformed []string
	for _, p := range probes {
		switch {
		case p.Literal:
			literal = append(literal, charName(p.Char))
		case p.Encoding == "not-reflected":
			missing = append(missing, charName(p.Char))
		case p.Encoding == "" || p.Encoding == "transformed":
			transformed = append(transformed, charName(p.Char))
		default:
			encoded = append(encoded, charName(p.Char)+" ("+p.Encoding+")")
		}
	}

	if len(literal) > 0 {
		severity = "high"
		verdict = fmt.Sprintf("literal %s reflected unescaped in %s context", strings.Join(literal, ", "), contextDesc(c))
		if breakoutDemonstrated(probes, c, atStart) {
			verdict += " - the characters that end this context survive; breakout is plausible"
		} else {
			verdict += " - note: no character that ends this context survived, so breakout is not demonstrated by this probe alone"
		}
		if csp.Present && !csp.AllowsInline() {
			verdict += "; CSP present and may block inline execution"
		}
		poc = pocFor(c)
		if isURLAttr(c.Attr) && atStart {
			for _, p := range probes {
				if p.Literal && (p.Char == ":" || p.Char == "/") {
					poc = "javascript:alert(document.domain)"
					break
				}
			}
		}
		return severity, verdict, poc
	}

	if len(encoded) > 0 {
		return "info", "dangerous characters are encoded in this context (" + strings.Join(encoded, ", ") + ")", ""
	}

	var detail []string
	if len(transformed) > 0 {
		detail = append(detail, "transformed/dropped: "+strings.Join(transformed, ", "))
	}
	if len(missing) > 0 {
		detail = append(detail, "not reflected: "+strings.Join(missing, ", "))
	}
	if len(detail) == 0 {
		detail = append(detail, "no probe returned data")
	}
	return "info", "dangerous characters dropped/transformed in this context (" + strings.Join(detail, "; ") + ")", ""
}

// breakoutDemonstrated reports whether any literal probe character actually
// ends the current syntactic context.
func breakoutDemonstrated(probes []charProbe, c Context, atStart bool) bool {
	lit := make(map[string]bool, len(probes))
	for _, p := range probes {
		if p.Literal {
			lit[p.Char] = true
		}
	}
	if isURLAttr(c.Attr) && atStart && (lit[":"] || lit["/"]) {
		return true
	}
	switch c.Kind {
	case KindText, KindRcdata, KindScriptRaw, KindStyle:
		return lit["<"]
	case KindAttrDQ:
		return lit["\""]
	case KindAttrSQ:
		return lit["'"]
	case KindAttrUQ:
		return lit[" "] || lit[">"] || lit["\""] || lit["'"] || lit["`"] || lit["="]
	case KindScriptDQ:
		return lit["\""] || lit["<"]
	case KindScriptSQ:
		return lit["'"] || lit["<"]
	case KindScriptTemplate:
		return lit["`"] || lit["<"]
	case KindComment:
		// A comment is closed by "-->", so both bytes must survive.
		return lit["-"] && lit[">"]
	}
	return false
}

// pocFor returns the canonical payload for a context.
func pocFor(c Context) string {
	switch c.Kind {
	case KindText, KindRcdata:
		return "<svg onload=alert(document.domain)>"
	case KindAttrDQ:
		return "\"><svg onload=alert(document.domain)>"
	case KindAttrSQ:
		return "'><svg onload=alert(document.domain)>"
	case KindAttrUQ:
		return " onmouseover=alert(document.domain) x="
	case KindScriptRaw:
		return "</script><svg onload=alert(document.domain)>"
	case KindScriptDQ:
		return "\";alert(document.domain);//"
	case KindScriptSQ:
		return "';alert(document.domain);//"
	case KindScriptTemplate:
		return "${alert(document.domain)}"
	case KindComment:
		return "--><svg onload=alert(document.domain)>"
	case KindStyle:
		return "</style><svg onload=alert(document.domain)>"
	}
	return "<svg onload=alert(document.domain)>"
}

// isURLAttr reports whether a value for this attribute is interpreted as a
// URL, where a literal ":" or "/" at the start enables a javascript: or
// protocol-relative payload.
func isURLAttr(a string) bool {
	switch a {
	case "href", "src", "action", "formaction", "data", "poster", "xlink:href", "cite", "background", "longdesc":
		return true
	}
	return false
}

// isJSScript reports whether a script type executes as JavaScript.
func isJSScript(typ string) bool {
	t := lowerString(strings.TrimSpace(typ))
	if t == "" {
		return true
	}
	if i := strings.IndexByte(t, ';'); i >= 0 {
		t = strings.TrimSpace(t[:i])
	}
	for _, want := range []string{"javascript", "ecmascript", "jscript", "module"} {
		if strings.Contains(t, want) {
			return true
		}
	}
	return false
}

var (
	jsUnicodeRe      = regexp.MustCompile(`^\\u[0-9a-fA-F]{4}`)
	jsHexRe          = regexp.MustCompile(`^\\x[0-9a-fA-F]{2}`)
	percentRe        = regexp.MustCompile(`^%[0-9a-fA-F]{2}`)
	htmlNumEntityRe  = regexp.MustCompile(`^&#(?:[xX][0-9a-fA-F]+|[0-9]+);`)
	htmlNameEntityRe = regexp.MustCompile(`^&[a-zA-Z][a-zA-Z0-9]{1,31};`)
)

// detectEncoding recognises a serialisation wrapper immediately following the
// marker and returns its name plus the decoded value.
func detectEncoding(after []byte) (match, decoded string) {
	match, decoded, _ = detectEncodingAt(after)
	return match, decoded
}

// detectEncodingAt is detectEncoding plus the byte length of the matched
// encoding, so callers can verify what follows it.
func detectEncodingAt(after []byte) (match, decoded string, n int) {
	if len(after) == 0 {
		return "", "", 0
	}
	if m := jsUnicodeRe.Find(after); m != nil {
		if v, err := strconv.ParseUint(string(m[2:]), 16, 32); err == nil {
			return "js-unicode-escape", string(rune(v)), len(m)
		}
	}
	if m := jsHexRe.Find(after); m != nil {
		if v, err := strconv.ParseUint(string(m[2:]), 16, 8); err == nil {
			return "js-hex-escape", string([]byte{byte(v)}), len(m)
		}
	}
	if m := percentRe.Find(after); m != nil {
		if b, err := hex.DecodeString(string(m[1:])); err == nil {
			return "percent-encoding", string(b), len(m)
		}
	}
	if m := htmlNumEntityRe.Find(after); m != nil {
		return "html-numeric-entity", html.UnescapeString(string(m)), len(m)
	}
	if m := htmlNameEntityRe.Find(after); m != nil {
		dec := html.UnescapeString(string(m))
		if dec != string(m) {
			return "html-named-entity", dec, len(m)
		}
		return "html-entity-unknown", dec, len(m)
	}
	if len(after) >= 2 && after[0] == '\\' {
		switch after[1] {
		case '\'', '"', '`', '\\':
			return "js-backslash-escape", string(after[1]), 2
		}
	}
	return "", "", 0
}

// contextAt is classifyAt plus one narrow correction: when a reflection begins
// exactly at the first byte of an unquoted attribute value, scan.go is still
// in stateBeforeValue at that byte and reports "tag". Advancing one byte
// reveals the attribute-value context.
func contextAt(src []byte, idx int) Context {
	c := classifyAt(src, idx)
	if c.Kind != KindTag || idx >= len(src) {
		return c
	}
	if next := classifyAt(src, idx+1); next.Kind == KindAttrUQ && next.ValueStart == idx {
		return next
	}
	return c
}

// indexAll returns every (non-overlapping) start offset of needle in hay.
func indexAll(hay, needle []byte) []int {
	if len(needle) == 0 {
		return nil
	}
	var out []int
	off := 0
	for {
		i := bytes.Index(hay[off:], needle)
		if i < 0 {
			return out
		}
		out = append(out, off+i)
		off += i + 1
	}
}

// snippetAround returns a sanitised window around a reflection.
func snippetAround(src []byte, idx, length int) string {
	const window = 120
	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + length + window
	if end > len(src) {
		end = len(src)
	}
	var sb strings.Builder
	for _, c := range src[start:end] {
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			sb.WriteByte(' ')
		case c < 0x20 || c == 0x7f:
			sb.WriteByte('.')
		default:
			sb.WriteByte(c)
		}
	}
	s := sb.String()
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	if start > 0 {
		s = "..." + s
	}
	if end < len(src) {
		s += "..."
	}
	return s
}

// newMarker returns a random alphanumeric marker that cannot plausibly occur
// in a document by chance.
func newMarker() string {
	var b [1]byte
	n := 7
	if _, err := rand.Read(b[:]); err == nil {
		n = 6 + int(b[0])%5
	}
	return "kx" + randHex(n)
}

// randHex returns n random bytes as hex.
func randHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		x := uint64(time.Now().UnixNano()) | 1
		for i := range buf {
			x ^= x << 13
			x ^= x >> 7
			x ^= x << 17
			buf[i] = byte(x)
		}
	}
	return hex.EncodeToString(buf)
}

// probeSample renders the bytes following a marker for JSON/report output.
func probeSample(b []byte) string {
	const maxSample = 16
	if len(b) > maxSample {
		b = b[:maxSample]
	}
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			sb.WriteByte(' ')
		case c < 0x20 || c == 0x7f:
			sb.WriteByte('.')
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func contextDesc(c Context) string {
	d := c.Kind.String()
	if c.Tag != "" {
		d += " in <" + c.Tag + ">"
	}
	if c.Attr != "" {
		d += " attribute " + c.Attr
	}
	if c.ScriptType != "" {
		d += " (type=" + c.ScriptType + ")"
	}
	return d
}

func charName(s string) string {
	switch s {
	case " ":
		return "'space'"
	case "\t":
		return "'tab'"
	case "\n":
		return "'newline'"
	}
	return "'" + s + "'"
}
