package ui

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/codejavu-llc/dnshunt/pkg/dns"
)

func RenderProgressBar(percent float64, width int) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	filled := int(percent / 100 * float64(width))
	return CBGreen + strings.Repeat("█", filled) + CDim + strings.Repeat("░", width-filled) + CReset
}

func FormatDuration(seconds float64) string {
	duration := time.Duration(seconds * float64(time.Second)).Round(time.Second)
	if duration < time.Minute {
		return duration.String()
	}
	return fmt.Sprintf("%dm%02ds", int(duration.Minutes()), int(duration.Seconds())%60)
}

func ProgressTicker(ctx context.Context, stats *dns.Stats, output io.Writer, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			render(stats, output)
			fmt.Fprint(output, "\r\033[K")
			return
		case <-ticker.C:
			render(stats, output)
		}
	}
}

func render(stats *dns.Stats, output io.Writer) {
	processed, success, failed, wildcards, queries, total := stats.GetCounts()
	elapsed := stats.ElapsedSeconds()
	var percent, queryRate float64
	if total > 0 {
		percent = float64(processed) / float64(total) * 100
	}
	if elapsed > 0 {
		queryRate = float64(queries) / elapsed
	}
	if total <= 0 {
		fmt.Fprintf(output, "\r%s%d%s processed  %s✓ %d%s  %s✗ %d%s  %s≈ %d%s  %s%.0f q/s%s   ",
			CBCyan, processed, CReset, CBGreen, success, CReset, CBRed, failed, CReset,
			CBYellow, wildcards, CReset, CBBlue, queryRate, CReset)
		return
	}
	eta := "--"
	if processed > 0 && total > processed {
		targetRate := float64(processed) / elapsed
		eta = FormatDuration(float64(total-processed) / targetRate)
	}
	fmt.Fprintf(output, "\r[%s] %s%5.1f%%%s  %s%d%s/%d  %s✓ %d%s  %s✗ %d%s  %s≈ %d%s  %s%.0f q/s%s  ETA %s   ",
		RenderProgressBar(percent, 20), CBYellow, percent, CReset, CBCyan, processed, CReset, total,
		CBGreen, success, CReset, CBRed, failed, CReset, CBYellow, wildcards, CReset,
		CBBlue, queryRate, CReset, eta)
}
