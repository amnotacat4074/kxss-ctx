# kxss-ctx

`kxss-ctx` is a context-aware reflected-XSS scanner. It is a small, dependency-free
Go rewrite of the idea behind [kxss](https://github.com/Emoe/kxss): find
parameters whose value comes back in the response, then decide whether that
reflection can actually break out of its HTML/JS context.

The difference is the word *context*. A `"` reflected inside a JSON string is
inert. The same `"` reflected inside a double-quoted attribute is an injection.
kxss reports the reflection; kxss-ctx reports where it landed and which
characters, if any, survive verbatim there.

## Install

```
go install github.com/amnotacat4074/kxss-ctx@latest
```

Or build from source:

```
git clone https://github.com/amnotacat4074/kxss-ctx
cd kxss-ctx
go build -o kxss-ctx .
```

Requires Go 1.21+. There are no third-party modules.

## Usage

Non-HTML responses (JavaScript, JSON, plain text) are reported as `info` with context `non-html`: a browser does not parse them as markup, so a literal `<` there is not an HTML breakout.

```
# one URL; every query parameter is tested
kxss-ctx -u 'https://example.test/search?q=hello&page=1'

# many URLs
kxss-ctx -f urls.txt

# pipeline
cat urls.txt | kxss-ctx

# JSON for tooling
kxss-ctx -json -f urls.txt

# noisy target: only medium and above
kxss-ctx -u 'https://example.test/search?q=1' -min-severity medium

# authenticated / header-sensitive targets
kxss-ctx -u 'https://example.test/?q=1' -cookie 'session=abc' -H 'X-Forwarded-Host: example.test' -H 'Origin: https://example.test'

# slow down, or allow redirects (off by default, see below)
kxss-ctx -u 'https://example.test/?q=1' -rate 2
kxss-ctx -u 'https://example.test/?q=1' -follow
```

Flags:

| flag | default | meaning |
| --- | --- | --- |
| `-u` | | single URL to test; must contain a query string |
| `-f` | | file of URLs, one per line (`-` for stdin) |
| `-json` | off | emit one JSON array of findings |
| `-c` | 10 | concurrent workers |
| `-rate` | 10 | global requests/second (`0` = unlimited) |
| `-timeout` | 15s | per-request timeout |
| `-follow` | off | follow redirects. **Off by default** so the scan cannot wander onto a host that is not in scope; redirect responses are still inspected for reflection in `Location`. |
| `-k` | off | skip TLS certificate verification |
| `-ua` | `kxss-ctx/1.0 (...)` | User-Agent. The tool advertises itself rather than pretending to be a browser. |
| `-cookie` | | raw `Cookie` header value |
| `-H` | | extra request header, `Name: value`; repeatable |
| `-max-occ` | 3 | maximum reflections to analyse per parameter |
| `-v` | off | diagnostics on stderr |
| `-color` | `auto` | ANSI colour for the severity tag only: `auto` (only when stdout is a terminal), `always`, `never`. `NO_COLOR` disables `auto`; `-json` is never coloured. |
| `-min-severity` | `low` | minimum severity to report (`info`, `low`, `medium`, `high`). Lower-severity findings are omitted from both human and JSON output and counted as suppressed in the summary. |

URLs without a scheme are treated as `https://`.

Exit status is `0` after a scan regardless of findings. Usage or I/O errors
exit `2`; an error writing JSON exits `1`.

After every scan a one-line accounting goes to stderr — tasks scanned,
requests made, findings per severity, and how many were filtered by
`-min-severity` (e.g. `3 high, 1 low, 412 info suppressed`). It stays on
stderr so `-json` output remains machine-parseable.

## What it does

1. Generates a random marker (`kx` + 12–20 hex characters) and substitutes it
   for one query parameter at a time.
2. Fetches the URL once. If the marker appears in a `Location` header it emits
   a `redirect-location` finding: `high` with an open-redirect candidate PoC
   only when the target is cross-origin, `info` for same-origin absolute and
   relative bounces (return-URL and locale redirects are routine, not bugs).
3. Finds every marker occurrence in the body (up to `-max-occ`) and classifies
   the byte-level syntactic context around it with a hand-written HTML scanner
   (`scan.go`). This is why byte offsets are available: standard tokenizers do
   not expose them or the original attribute quoting style.
4. For each occurrence, probes only the characters that can end *that*
   context. Each probe sends `marker + char + random-suffix` and checks that
   the character (or a recognised encoding of it) sits immediately before the
   suffix. The suffix prevents static HTML that follows the reflection from
   being mistaken for the reflected character.
5. Reports a verdict, a candidate PoC for the context, and whether a CSP is
   likely to block inline execution.

### Context table

| context | probe characters | example PoC |
| --- | --- | --- |
| `html-text` | `<` | `<svg onload=alert(document.domain)>` |
| `rcdata` (`<textarea>`, `<title>`) | `<`, `/` (only `</tag` ends it) | `<svg onload=alert(document.domain)>` |
| `attr-double-quoted` | `"`, `<` | `"><svg onload=alert(document.domain)>` |
| `attr-single-quoted` | `'`, `<` | `'><svg onload=alert(document.domain)>` |
| `attr-unquoted` | space, `>`, `"`, `'`, `` ` ``, `=`, `<` | ` onmouseover=alert(document.domain) x=` |
| `script-code` | `<`, `/` (only `</script` ends it) | `</script><svg onload=alert(document.domain)>` |
| `script-double-quoted` | `"`, `<`, `/` | `";alert(document.domain);//` |
| `script-single-quoted` | `'`, `<`, `/` | `';alert(document.domain);//` |
| `script-template-literal` | `` ` ``, `$`, `<`, `/` | `${alert(document.domain)}` |
| `html-comment` | `>`, `-` (both needed for `-->`) | `--><svg onload=alert(document.domain)>` |
| `style` | `<`, `/` (only `</style` ends it) | `</style><svg onload=alert(document.domain)>` |
| `tag` | none (not probed) | — |
| `redirect-location` | — | cross-origin `Location` only |

A `<script>` whose `type` is not JavaScript (JSON, `__NEXT_DATA__`, templates)
is treated as data, not code: quotes are inert there, so only `<` and `/` are
probed, and a breakout needs both.

For URL-valued attributes (`href`, `src`, `action`, `formaction`, `data`,
`poster`, `xlink:href`, `cite`, `background`, `longdesc`), when the reflection
starts the value, `:` and `/` are probed too. If either survives verbatim the
finding is `low` (scheme-injection candidate) with
`javascript:alert(document.domain)` as a *candidate* PoC: an allow-list or
browser behaviour may still stop it, so it is never reported as reflected XSS.

Encodings recognised as "the character is there, just wrapped": HTML numeric
and named entities, JavaScript `\uXXXX` and `\xXX`, percent-encoding, and a
leading JS backslash escape (`\"`, `\'`, `` \` ``, `\\`).

### Severity

* `high` — the structural terminator of the context survived verbatim: `<` in
  text, the matching quote in a quoted attribute, space/`>` in an unquoted
  attribute, `-->` in a comment, `</tag` in raw-text/RCDATA/style, a JS quote
  in a script string, or a cross-origin redirect target. Only these findings
  carry an executable PoC.
* `low` — a URL-valued attribute is fully attacker-controlled (`:`/`/`
  survive). A scheme-injection *candidate*; verify any allow-list.
* `info` — the reflection is real but not a breakout: the dangerous characters
  were encoded, transformed or dropped, only non-terminating characters
  survived (e.g. a literal `<` inside a quoted attribute), or the redirect
  target was relative/same-origin. No PoC is emitted for these.

## Honest limits

This is a reflection analyser, not a browser. Read the verdict, not just the
severity.

* **No JavaScript is executed and no DOM is built.** Contexts created by
  client-side rendering or hydration are invisible to it. A reflection found by
  a server-side scan may be harmless after hydration, and a browser-only sink
  will not be found at all.
* **It cannot prove execution.** "High" means the breakout characters survived
  the server's transformation. It does not mean the page's JavaScript did not
  sanitise or remove the payload afterwards. Confirm with a browser (or a
  tooling-grade scanner) before reporting.
* **Reflection-based only.** Stored XSS, DOM-based XSS and blind/OOB payloads
  are out of scope.
* **Entity-encoded characters are treated as non-breaking.** This is correct
  for HTML text and quoted attributes, but URL-valued attributes are special:
  browsers resolve entities in `href`/`src`, so something like
  `javascript&#58;alert(1)` can still execute. Such cases are reported `info`
  with the encoding named; review URL attributes by hand.
* **Encoding detection is pattern-based.** Custom escapes, double encoding,
  Unicode normalisation or partial truncation are reported as `transformed`
  rather than guessed at.
* **Only the first `-max-occ` reflections** are examined, and probes assume the
  reflection order is stable between requests. A page whose reflection positions
  change per request may be misclassified.
* **The scanner follows no redirects by default.** This keeps the scan on the
  target you were authorised to test; use `-follow` deliberately, and only when
  every hop is in scope.
* **Rate limiting is a friendliness control, not a guarantee.** Keep `-rate`
  and `-c` low on production systems.

## Authorised use

Use this only against systems you own or have explicit written permission to
test. Unauthorised scanning may be unlawful and is not condoned by the author.
The default `-follow=false` and conservative rate limit exist to reduce
accidental scope creep; you remain responsible for how you run it.

## License

MIT — see `LICENSE`. Copyright (c) 2026 amnotacat4074.
