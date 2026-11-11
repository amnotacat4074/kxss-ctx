package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSeverityRankOrdering(t *testing.T) {
	order := []string{"info", "low", "medium", "high"}
	for i := 1; i < len(order); i++ {
		if severityRank[order[i-1]] >= severityRank[order[i]] {
			t.Fatalf("severityRank not strictly increasing: %s=%d, %s=%d",
				order[i-1], severityRank[order[i-1]], order[i], severityRank[order[i]])
		}
	}
	for _, sev := range order {
		if _, ok := severityRank[sev]; !ok {
			t.Errorf("severity %q missing from severityRank", sev)
		}
	}
}

func TestColorEnabled(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		jsonOut bool
		noColor bool
		isTTY   bool
		want    bool
	}{
		{"auto tty", "auto", false, false, true, true},
		{"auto pipe", "auto", false, false, false, false},
		{"auto NO_COLOR on tty", "auto", false, true, true, false},
		{"always pipe", "always", false, false, false, true},
		{"always NO_COLOR", "always", false, true, false, true},
		{"never tty", "never", false, false, true, false},
		{"auto json on tty", "auto", true, false, true, false},
		{"always json", "always", true, false, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := colorEnabled(tc.mode, tc.jsonOut, tc.noColor, tc.isTTY); got != tc.want {
				t.Fatalf("colorEnabled(%q, json=%v, noColor=%v, tty=%v) = %v, want %v",
					tc.mode, tc.jsonOut, tc.noColor, tc.isTTY, got, tc.want)
			}
		})
	}
}

func TestFormatSeverity(t *testing.T) {
	for _, sev := range []string{"high", "medium", "low", "info"} {
		colored := formatSeverity(sev, true)
		if !strings.Contains(colored, colorFor(sev)) || !strings.Contains(colored, ansiReset) {
			t.Errorf("formatSeverity(%q, true) = %q, missing expected SGR", sev, colored)
		}
		if got := formatSeverity(sev, false); got != sev {
			t.Errorf("formatSeverity(%q, false) = %q, want plain", sev, got)
		}
	}
	if got := formatSeverity("unknown", true); got != "unknown" {
		t.Errorf("unknown severity should not be coloured, got %q", got)
	}
}

func TestPrintFindingColoursOnlySeverity(t *testing.T) {
	f := finding{Severity: "high", URL: "https://example.test/?q=1", Param: "q", Kind: "html-text", Offset: 1, Status: 200}
	var plain, colored bytes.Buffer
	printFinding(&plain, f, false)
	printFinding(&colored, f, true)
	if strings.ContainsAny(plain.String(), "\x1b") {
		t.Errorf("plain output contains ANSI escape")
	}
	if !strings.HasPrefix(colored.String(), "["+ansiHigh+"high"+ansiReset+"]") {
		t.Errorf("coloured output does not start with the coloured severity token:\n%q", colored.String())
	}
	// Everything after the severity token must be identical.
	plainRest := strings.TrimPrefix(plain.String(), "[high]")
	coloredRest := strings.TrimPrefix(colored.String(), "["+ansiHigh+"high"+ansiReset+"]")
	if plainRest != coloredRest {
		t.Errorf("colour leaked past the severity token:\nplain=%q\ncolored=%q", plainRest, coloredRest)
	}
}

func TestPrintSummary(t *testing.T) {
	reported := map[string]int{"high": 3, "low": 1}
	suppressed := map[string]int{"info": 412}
	var buf bytes.Buffer
	printSummary(&buf, 7, 1234, "low", reported, suppressed)
	got := buf.String()
	for _, want := range []string{"7 task(s)", "1234 request(s)", "3 high", "1 low", "412 info suppressed"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q missing %q", got, want)
		}
	}

	buf.Reset()
	printSummary(&buf, 1, 2, "high", map[string]int{}, map[string]int{"info": 2, "low": 1})
	got = buf.String()
	if !strings.Contains(got, "2 info suppressed") || !strings.Contains(got, "1 low suppressed") {
		t.Errorf("suppressed accounting missing from %q", got)
	}
}
