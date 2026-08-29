package reader

import (
	"context"
	"strings"
	"testing"
)

func TestStreamTargetsNormalizesDeduplicatesAndCounts(t *testing.T) {
	input := "\ufeffExample.COM.\n# comment\nhttps://api.example.com/path\nexample.com\n*.wild.example.com\ninvalid domain\n"
	out := make(chan string, 8)
	report, err := StreamTargets(context.Background(), strings.NewReader(input), out, true)
	close(out)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for target := range out {
		got = append(got, target)
	}
	want := []string{"example.com", "api.example.com", "wild.example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	if report.Emitted != 3 || report.Duplicates != 1 || report.Invalid != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestNormalizeTargetSupportsIDNIPAndServiceLabels(t *testing.T) {
	tests := map[string]string{
		"bücher.example":         "xn--bcher-kva.example",
		"192.0.2.1":              "192.0.2.1",
		"[2001:db8::1]":          "2001:db8::1",
		"_sip._tcp.example.com.": "_sip._tcp.example.com",
	}
	for input, want := range tests {
		got, err := NormalizeTarget(input)
		if err != nil {
			t.Errorf("NormalizeTarget(%q): %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeTarget(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCountTargetsCountsFinalLineWithoutNewline(t *testing.T) {
	report, err := CountTargets(strings.NewReader("one.example\n\n# skip\ntwo.example"), true)
	if err != nil {
		t.Fatal(err)
	}
	if report.Emitted != 2 {
		t.Fatalf("emitted = %d, want 2", report.Emitted)
	}
}
