package ui

import (
	"context"
	"fmt"
	"os"
	"strings"

	"dnshunt/pkg/dns"
)

func RenderProgressBar(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	return CBGreen + strings.Repeat("█", filled) + CDim + strings.Repeat("░", width-filled) + CReset
}

func FormatDuration(sec float64) string {
	if sec < 60 {
		return fmt.Sprintf("%.0fs", sec)
	}
	return fmt.Sprintf("%dm%ds", int(sec)/60, int(sec)%60)
}

func ProgressTicker(ctx context.Context, stats *dns.Stats, done chan struct{}) {
	defer close(done)
	for {
		select {
		case <-ctx.Done():
			render(stats)
			fmt.Fprintln(os.Stderr)
			return
		case <-stats.Ticker.C:
			render(stats)
		}
	}
}

func render(stats *dns.Stats) {
	proc, ok, fail, total := stats.GetCounts()
	elapsed := stats.ElapsedSeconds()
	var pct, rate float64
	if total > 0 {
		pct = float64(proc) / float64(total) * 100
	}
	if elapsed > 0 {
		rate = float64(proc) / elapsed
	}

	eta := "--"
	if rate > 0 && total > proc {
		eta = FormatDuration(float64(total-proc) / rate)
	}

	bar := RenderProgressBar(pct, 24)
	line := fmt.Sprintf("\r%s[%s] %s%5.1f%%%s  %s%d%s/%d  %s✓ %d%s  %s✗ %d%s  %s%.0f q/s%s  %sETA %s%s   ",
		CDim, bar, CBYellow, pct, CReset, CBCyan, proc, CReset, total, CBGreen, ok, CReset, CBRed, fail, CReset, CBBlue, rate, CReset, CBYellow, eta, CReset)
	fmt.Fprint(os.Stderr, line)
}