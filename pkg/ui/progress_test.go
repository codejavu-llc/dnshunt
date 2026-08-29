package ui

import (
	"strings"
	"testing"
)

func TestRenderProgressBarClampsPercentage(t *testing.T) {
	DisableColors()
	if got := RenderProgressBar(150, 4); got != "████" {
		t.Fatalf("overflow bar = %q", got)
	}
	if got := RenderProgressBar(-10, 4); got != "░░░░" {
		t.Fatalf("negative bar = %q", got)
	}
}

func TestFormatDuration(t *testing.T) {
	if got := FormatDuration(65); got != "1m05s" {
		t.Fatalf("duration = %q", got)
	}
	if got := FormatDuration(2.4); !strings.HasPrefix(got, "2s") {
		t.Fatalf("duration = %q", got)
	}
}
