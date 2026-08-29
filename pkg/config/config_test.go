package config

import (
	"bytes"
	"testing"
	"time"
)

func TestParseModernAndLegacyOptions(t *testing.T) {
	cfg, err := Parse([]string{
		"-t", "A,aaaa,CNAME,A",
		"-timeout", "1500",
		"-rc", "3",
		"-consensus", "2",
		"-retry", "4",
		"-jsonl",
		"example.com",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != 1500*time.Millisecond {
		t.Fatalf("timeout = %s", cfg.Timeout)
	}
	if got, want := len(cfg.QTypes), 3; got != want {
		t.Fatalf("record type count = %d, want %d", got, want)
	}
	if cfg.OutputFormat != "jsonl" || cfg.Consensus != 2 || cfg.Retries != 4 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestParseRejectsUnsafeValues(t *testing.T) {
	tests := [][]string{
		{"-c", "0"},
		{"-timeout", "0"},
		{"-retry", "0"},
		{"-rc", "2", "-consensus", "3"},
		{"-edns-size", "500"},
		{"-format", "xml"},
	}
	for _, args := range tests {
		if _, err := Parse(args, &bytes.Buffer{}); err == nil {
			t.Errorf("Parse(%v) unexpectedly succeeded", args)
		}
	}
}

func TestParseAllowsOptionsAfterPositionalTarget(t *testing.T) {
	cfg, err := Parse([]string{"example.com", "-rc", "2", "-consensus", "2", "-t", "AAAA"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Targets) != 1 || cfg.Targets[0] != "example.com" || cfg.ResolversEach != 2 || cfg.RecordTypes[0] != "AAAA" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}
