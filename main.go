package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"dnshunt/pkg/config"
	"dnshunt/pkg/dns"
	"dnshunt/pkg/reader"
	"dnshunt/pkg/runner"
	"dnshunt/pkg/ui"
	"dnshunt/pkg/writer"
)

var defaultResolvers = []string{
	"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
	"9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
}

func main() {
	cfg, ok := config.Parse()
	if !ok {
		return
	}

	ui.PrintBanner()

	totalTargets, err := reader.CountLines(cfg.TargetList)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[!]%s error reading target list: %v\n", ui.CBRed, ui.CReset, err)
		os.Exit(1)
	}

	var resolvers []string

	// File resolvers (-r)
	if cfg.ResolverFile != "" {
		resChan := make(chan string, 100)
		go func() {
			_ = reader.StreamLines(context.Background(), cfg.ResolverFile, resChan)
			close(resChan)
		}()
		for r := range resChan {
			if n := dns.NormalizeResolver(r); n != "" {
				resolvers = append(resolvers, n)
			}
		}
	}

	// Comma-separated resolvers (-R)
	if cfg.ResolverList != "" {
		for _, r := range strings.Split(cfg.ResolverList, ",") {
			if n := dns.NormalizeResolver(r); n != "" {
				resolvers = append(resolvers, n)
			}
		}
	}

	// Fallback to default resolvers
	if len(resolvers) == 0 {
		for _, r := range defaultResolvers {
			if n := dns.NormalizeResolver(r); n != "" {
				resolvers = append(resolvers, n)
			}
		}
	}

	outWriter, err := writer.NewWriter(cfg.OutputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[!]%s failed to initialize output file: %v\n", ui.CBRed, ui.CReset, err)
		os.Exit(1)
	}
	if outWriter != nil {
		defer outWriter.Close()
	}

	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	stats := dns.NewStats(totalTargets)
	progCtx, progCancel := context.WithCancel(rootCtx)
	progDone := make(chan struct{})

	go ui.ProgressTicker(progCtx, stats, progDone)

	runner.Run(rootCtx, cfg, resolvers, stats, outWriter)

	progCancel()
	<-progDone

	elapsed := stats.ElapsedSeconds()
	proc, okCount, failCount, _ := stats.GetCounts()
	fmt.Printf("\n%s┌─ Summary ──────────────────────────────────────────┐%s\n", ui.CBGreen, ui.CReset)
	fmt.Printf("%s│%s %-15s %s%d%s\n", ui.CBGreen, ui.CReset, "Processed:", ui.CBCyan, proc, ui.CReset)
	fmt.Printf("%s│%s %-15s %s%d%s\n", ui.CBGreen, ui.CReset, "Resolved:", ui.CBGreen, okCount, ui.CReset)
	fmt.Printf("%s│%s %-15s %s%d%s\n", ui.CBGreen, ui.CReset, "Failed:", ui.CBRed, failCount, ui.CReset)
	fmt.Printf("%s│%s %-15s %s%s%s\n", ui.CBGreen, ui.CReset, "Elapsed:", ui.CBYellow, ui.FormatDuration(elapsed), ui.CReset)
	if elapsed > 0 {
		fmt.Printf("%s│%s %-15s %s%.1f q/s%s\n", ui.CBGreen, ui.CReset, "Throughput:", ui.CBBlue, float64(proc)/elapsed, ui.CReset)
	}
	fmt.Printf("%s└────────────────────────────────────────────────────┘%s\n", ui.CBGreen, ui.CReset)
}
