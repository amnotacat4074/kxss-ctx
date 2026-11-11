package main

import (
	"net/http"
	"strings"
	"testing"
)

func httpHeader(name, value string) http.Header {
	h := http.Header{}
	h.Set(name, value)
	return h
}

func markerOffset(t *testing.T, src, marker string) int {
	t.Helper()
	i := strings.Index(src, marker)
	if i < 0 {
		t.Fatalf("marker %q not present in fixture %q", marker, src)
	}
	return i
}

func TestClassifyAt(t *testing.T) {
	const m = "MARKER"
	tests := []struct {
		name           string
		src            string
		wantKind       Kind
		wantTag        string
		wantAttr       string
		wantScriptType string
		wantValueStart int // -1 means "same as marker offset"
	}{
		{
			name:     "html-text",
			src:      "<p>hello MARKER world</p>",
			wantKind: KindText, wantTag: "p",
		},
		{
			name:     "attr-double-quoted",
			src:      `<input value="MARKER">`,
			wantKind: KindAttrDQ, wantTag: "input", wantAttr: "value",
			wantValueStart: -1,
		},
		{
			name:     "attr-single-quoted",
			src:      `<a href='MARKER'>x</a>`,
			wantKind: KindAttrSQ, wantTag: "a", wantAttr: "href",
			wantValueStart: -1,
		},
		{
			name:     "attr-unquoted",
			src:      `<input value=xMARKER>`,
			wantKind: KindAttrUQ, wantTag: "input", wantAttr: "value",
			wantValueStart: -2, // start of "x" one byte before the marker
		},
		{
			name:     "comment",
			src:      "<div><!-- MARKER --></div>",
			wantKind: KindComment, wantTag: "div",
		},
		{
			name:     "script-code",
			src:      "<script>var x = MARKER;</script>",
			wantKind: KindScriptRaw, wantTag: "script",
		},
		{
			name:     "script-single-quoted",
			src:      "<script>var x = 'MARKER';</script>",
			wantKind: KindScriptSQ, wantTag: "script",
		},
		{
			name:     "script-double-quoted",
			src:      `<script>var x = "MARKER";</script>`,
			wantKind: KindScriptDQ, wantTag: "script",
		},
		{
			name:           "script-json",
			src:            `<script type="application/json">MARKER</script>`,
			wantKind:       KindScriptRaw,
			wantTag:        "script",
			wantScriptType: "application/json",
			wantValueStart: -3, // ValueStart still points at the type attribute
		},
		{
			name:     "style",
			src:      "<style>body{color:MARKER}</style>",
			wantKind: KindStyle, wantTag: "style",
		},
		{
			name:     "textarea",
			src:      "<textarea>MARKER</textarea>",
			wantKind: KindRcdata, wantTag: "textarea",
		},
		{
			name:     "title",
			src:      "<title>MARKER</title>",
			wantKind: KindRcdata, wantTag: "title",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idx := markerOffset(t, tc.src, m)
			got := classifyAt([]byte(tc.src), idx)
			if got.Kind != tc.wantKind {
				t.Errorf("Kind = %s, want %s (context %+v)", got.Kind, tc.wantKind, got)
			}
			if got.Tag != tc.wantTag {
				t.Errorf("Tag = %q, want %q", got.Tag, tc.wantTag)
			}
			if got.Attr != tc.wantAttr {
				t.Errorf("Attr = %q, want %q", got.Attr, tc.wantAttr)
			}
			if got.ScriptType != tc.wantScriptType {
				t.Errorf("ScriptType = %q, want %q", got.ScriptType, tc.wantScriptType)
			}
			switch tc.wantValueStart {
			case -1:
				if got.ValueStart != idx {
					t.Errorf("ValueStart = %d, want marker offset %d", got.ValueStart, idx)
				}
			case -2:
				if got.ValueStart != idx-1 {
					t.Errorf("ValueStart = %d, want %d", got.ValueStart, idx-1)
				}
			case -3:
				// ValueStart is not meaningful here (stale from an earlier
				// attribute); nothing to assert.
			default:
				if got.ValueStart != tc.wantValueStart {
					t.Errorf("ValueStart = %d, want %d", got.ValueStart, tc.wantValueStart)
				}
			}
		})
	}
}

func TestContextAtUnquotedStart(t *testing.T) {
	src := []byte(`<input value=kxdeadbeef>`)
	idx := strings.Index(string(src), "kxdeadbeef")
	if idx < 0 {
		t.Fatal("marker missing")
	}
	// classifyAt alone is still in stateBeforeValue here.
	if got := classifyAt(src, idx); got.Kind != KindTag {
		t.Fatalf("classifyAt = %s, expected the tag-state quirk this helper corrects", got.Kind)
	}
	got := contextAt(src, idx)
	if got.Kind != KindAttrUQ {
		t.Errorf("contextAt = %s, want attr-unquoted", got.Kind)
	}
	if got.Attr != "value" || got.ValueStart != idx {
		t.Errorf("contextAt attr=%q valueStart=%d, want value/%d", got.Attr, got.ValueStart, idx)
	}
}

func TestDangerousFor(t *testing.T) {
	tests := []struct {
		ctx     Context
		atStart bool
		want    string
	}{
		{Context{Kind: KindText}, false, "<"},
		{Context{Kind: KindRcdata}, false, "<"},
		{Context{Kind: KindAttrDQ}, false, "\"<"},
		{Context{Kind: KindAttrSQ}, false, "'<"},
		{Context{Kind: KindAttrUQ}, false, " >\"'`=<"},
		{Context{Kind: KindScriptRaw}, false, "<"},
		{Context{Kind: KindScriptDQ}, false, "\"<"},
		{Context{Kind: KindScriptSQ}, false, "'<"},
		{Context{Kind: KindScriptTemplate}, false, "`$<"},
		{Context{Kind: KindComment}, false, ">-"},
		{Context{Kind: KindStyle}, false, "<"},
		{Context{Kind: KindTag}, false, ""},
		{Context{Kind: KindAttrDQ, Attr: "href"}, true, "\"<:/"},
		{Context{Kind: KindAttrDQ, Attr: "href"}, false, "\"<"},
		{Context{Kind: KindText, Attr: "src"}, true, "<"},
	}
	for _, tc := range tests {
		if got := string(dangerousFor(tc.ctx, tc.atStart)); got != tc.want {
			t.Errorf("dangerousFor(%s, attr=%q, atStart=%v) = %q, want %q", tc.ctx.Kind, tc.ctx.Attr, tc.atStart, got, tc.want)
		}
	}
}

func TestDetectEncoding(t *testing.T) {
	tests := []struct {
		after    string
		wantDec  string
		wantSome bool
	}{
		{"&#34;rest", `"`, true},
		{"&#x22;rest", `"`, true},
		{"&quot;rest", `"`, true},
		{"\\u0022rest", `"`, true},
		{"\\x22rest", `"`, true},
		{"%22rest", `"`, true},
		{"\\\"rest", `"`, true},
		{"plain", "", false},
	}
	for _, tc := range tests {
		_, dec := detectEncoding([]byte(tc.after))
		if tc.wantSome && dec != tc.wantDec {
			t.Errorf("detectEncoding(%q) decoded %q, want %q", tc.after, dec, tc.wantDec)
		}
		if !tc.wantSome && dec != "" {
			t.Errorf("detectEncoding(%q) decoded %q, want no match", tc.after, dec)
		}
	}
}

func TestIsURLAttr(t *testing.T) {
	for _, a := range []string{"href", "src", "action", "formaction", "data", "poster", "xlink:href", "cite", "background", "longdesc"} {
		if !isURLAttr(a) {
			t.Errorf("isURLAttr(%q) = false, want true", a)
		}
	}
	for _, a := range []string{"", "value", "onclick", "class"} {
		if isURLAttr(a) {
			t.Errorf("isURLAttr(%q) = true, want false", a)
		}
	}
}

func TestAssessLiteralVsEncoded(t *testing.T) {
	ctx := Context{Kind: KindAttrDQ, Tag: "input", Attr: "value"}
	sealed := cspInfo{Present: true, Directives: map[string]string{"script-src": "'self'"}}

	sev, verdict, poc := assess(ctx, []charProbe{
		{Char: `"`, Literal: true},
		{Char: "<", Literal: true},
	}, sealed, true)
	if sev != "high" {
		t.Errorf("literal quotes: severity = %q, want high", sev)
	}
	if !strings.Contains(verdict, "CSP present") {
		t.Errorf("literal quotes: verdict should mention the CSP, got %q", verdict)
	}
	if poc != "\"><svg onload=alert(document.domain)>" {
		t.Errorf("poc = %q", poc)
	}

	sev, verdict, poc = assess(ctx, []charProbe{
		{Char: `"`, Encoding: "html-numeric-entity"},
		{Char: "<", Encoding: "html-numeric-entity"},
	}, cspInfo{}, true)
	if sev != "info" || !strings.Contains(verdict, "encoded") {
		t.Errorf("encoded quotes: got %q / %q, want info/encoded", sev, verdict)
	}
	if poc != "" {
		t.Errorf("encoded quotes: no PoC should be offered, got %q", poc)
	}

	// A literal "<" in a double-quoted attribute does not end the context.
	sev, verdict, _ = assess(ctx, []charProbe{{Char: "<", Literal: true}}, cspInfo{}, false)
	if sev != "high" {
		t.Errorf("literal <: severity = %q, want high (spec)", sev)
	}
	if !strings.Contains(verdict, "not demonstrated") {
		t.Errorf("literal <: verdict should carry the breakout caveat, got %q", verdict)
	}
}

func TestPocFor(t *testing.T) {
	cases := map[Kind]string{
		KindText:           "<svg onload=alert(document.domain)>",
		KindRcdata:         "<svg onload=alert(document.domain)>",
		KindAttrDQ:         "\"><svg onload=alert(document.domain)>",
		KindAttrSQ:         "'><svg onload=alert(document.domain)>",
		KindAttrUQ:         " onmouseover=alert(document.domain) x=",
		KindScriptRaw:      "</script><svg onload=alert(document.domain)>",
		KindScriptDQ:       "\";alert(document.domain);//",
		KindScriptSQ:       "';alert(document.domain);//",
		KindScriptTemplate: "${alert(document.domain)}",
		KindComment:        "--><svg onload=alert(document.domain)>",
		KindStyle:          "</style><svg onload=alert(document.domain)>",
	}
	for k, want := range cases {
		if got := pocFor(Context{Kind: k}); got != want {
			t.Errorf("pocFor(%s) = %q, want %q", k, got, want)
		}
	}
}

func TestParseCSP(t *testing.T) {
	h := httpHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")
	c := parseCSP(h, nil)
	if !c.Present || !c.AllowsInline() {
		t.Errorf("unsafe-inline policy: Present=%v AllowsInline=%v, want true/true", c.Present, c.AllowsInline())
	}
	if c.Directives["script-src"] != "'self' 'unsafe-inline'" {
		t.Errorf("script-src = %q", c.Directives["script-src"])
	}

	c = parseCSP(httpHeader("Content-Security-Policy", "script-src 'nonce-abc' 'unsafe-inline'"), nil)
	if c.AllowsInline() {
		t.Error("nonce alongside unsafe-inline must disable inline")
	}

	meta := []byte(`<html><head><meta content="script-src 'self'" http-equiv="Content-Security-Policy"></head></html>`)
	c = parseCSP(nil, meta)
	if !c.Present || c.AllowsInline() {
		t.Errorf("meta CSP: Present=%v AllowsInline=%v, want true/false", c.Present, c.AllowsInline())
	}
	if got := parseCSP(nil, []byte("<html></html>")); got.Present {
		t.Error("no CSP should yield Present=false")
	}
	if !(cspInfo{}).AllowsInline() {
		t.Error("absent CSP must allow inline")
	}
}

func TestIndexAllAndSnippet(t *testing.T) {
	got := indexAll([]byte("aXbXc"), []byte("X"))
	if len(got) != 2 || got[0] != 1 || got[1] != 3 {
		t.Errorf("indexAll = %v", got)
	}
	if n := indexAll([]byte("abc"), []byte("")); n != nil {
		t.Errorf("indexAll with empty needle = %v, want nil", n)
	}
	snip := snippetAround([]byte("line1\nline2\nMARKER\nline4"), 14, 6)
	if strings.ContainsAny(snip, "\n\r\t") {
		t.Errorf("snippet still contains control characters: %q", snip)
	}
	if !strings.Contains(snip, "MARKER") {
		t.Errorf("snippet lost the marker: %q", snip)
	}
}

func TestNewMarkerShape(t *testing.T) {
	seen := make(map[string]bool, 32)
	for i := 0; i < 32; i++ {
		m := newMarker()
		if !strings.HasPrefix(m, "kx") {
			t.Fatalf("marker %q does not start with kx", m)
		}
		if len(m) < 2+12 || len(m) > 2+20 {
			t.Fatalf("marker %q has unexpected length %d", m, len(m))
		}
		for _, c := range m[2:] {
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Fatalf("marker %q contains non-hex character %q", m, c)
			}
		}
		if seen[m] {
			t.Fatalf("marker %q generated twice", m)
		}
		seen[m] = true
	}
}
