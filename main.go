package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/codejavu-llc/dnshunt/pkg/config"
	"github.com/codejavu-llc/dnshunt/pkg/dns"
	"github.com/codejavu-llc/dnshunt/pkg/reader"
	"github.com/codejavu-llc/dnshunt/pkg/runner"
	"github.com/codejavu-llc/dnshunt/pkg/ui"
	"github.com/codejavu-llc/dnshunt/pkg/writer"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var defaultResolvers = []string{
	// Interleave providers so every five-endpoint window spans Cloudflare,
	// Google, Quad9, and OpenDNS before repeating an operator.
	"1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222",
	"1.0.0.1", "8.8.4.4", "149.112.112.112", "208.67.220.220",
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cfg, err := config.Parse(args, stderr)
	if errors.Is(err, config.ErrHelp) {
		configureColor(false, stdout, cfg)
		ui.PrintHelp(stdout)
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "dnshunt: %v\n", err)
		fmt.Fprintln(stderr, "Try 'dnshunt -h' for usage.")
		return 2
	}
	if cfg.ShowVersion {
		fmt.Fprintf(stdout, "dnshunt %s (commit %s, built %s)\n", version, commit, date)
		return 0
	}

	stderrTTY := isTerminal(stderr)
	configureColor(stderrTTY, stderr, cfg)
	if cfg.TargetList == "" && len(cfg.Targets) == 0 && isTerminal(stdin) {
		fmt.Fprintln(stderr, "dnshunt: provide targets with -l, positional arguments, or stdin")
		fmt.Fprintln(stderr, "Try 'dnshunt -h' for usage.")
		return 2
	}
	if stderrTTY && !cfg.Silent {
		ui.PrintBanner(stderr)
	}

	resolvers, err := loadResolvers(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "dnshunt: %v\n", err)
		return 1
	}
	if cfg.ResolversEach > len(resolvers) {
		cfg.ResolversEach = len(resolvers)
	}
	if cfg.Consensus > cfg.ResolversEach {
		fmt.Fprintf(stderr, "dnshunt: consensus %d exceeds the %d available resolver(s)\n", cfg.Consensus, cfg.ResolversEach)
		return 2
	}
	if cfg.WildcardDomain != "" {
		cfg.WildcardDomain, err = reader.NormalizeTarget(cfg.WildcardDomain)
		if err != nil {
			fmt.Fprintf(stderr, "dnshunt: invalid wildcard domain: %v\n", err)
			return 2
		}
	}

	input, closeInput, total, err := prepareInput(cfg, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "dnshunt: prepare input: %v\n", err)
		return 1
	}
	defer closeInput()
	total *= int64(len(cfg.QTypes))
	stats := dns.NewStats(total)

	outputOptions := writer.Options{
		Format:          cfg.OutputFormat,
		Silent:          cfg.Silent,
		Verbose:         cfg.Verbose,
		IncludeFailures: cfg.IncludeFailures,
	}
	consoleWriter, err := writer.New(stdout, outputOptions)
	if err != nil {
		fmt.Fprintf(stderr, "dnshunt: initialize output: %v\n", err)
		return 1
	}
	var fileWriter writer.ResultWriter
	if cfg.OutputFile != "" {
		fileWriter, err = writer.NewFile(cfg.OutputFile, outputOptions)
		if err != nil {
			_ = consoleWriter.Close()
			fmt.Fprintf(stderr, "dnshunt: initialize output file: %v\n", err)
			return 1
		}
	}
	output := writer.Multi(consoleWriter, fileWriter)

	progressEnabled := stderrTTY && !cfg.NoProgress && !cfg.Silent
	progressCtx, stopProgress := context.WithCancel(ctx)
	progressDone := make(chan struct{})
	if progressEnabled {
		go ui.ProgressTicker(progressCtx, stats, stderr, progressDone)
	}

	report, runErr := runner.Run(ctx, cfg, resolvers, stats, output, input)
	if progressEnabled {
		stopProgress()
		<-progressDone
	} else {
		stopProgress()
	}
	closeErr := output.Close()
	if runErr == nil {
		runErr = closeErr
	}

	if (stderrTTY && !cfg.Silent) || cfg.Stats {
		ui.PrintSummary(stderr, stats, report.Invalid, report.Duplicates)
	} else if report.Invalid > 0 && !cfg.Silent {
		fmt.Fprintf(stderr, "dnshunt: skipped %d invalid target(s)\n", report.Invalid)
	}
	if runErr != nil {
		if errors.Is(runErr, context.Canceled) && ctx.Err() != nil {
			fmt.Fprintln(stderr, "dnshunt: interrupted")
			return 130
		}
		fmt.Fprintf(stderr, "dnshunt: %v\n", runErr)
		return 1
	}
	return 0
}

func loadResolvers(cfg *config.Config) ([]string, error) {
	var raw []string
	if cfg.ResolverFile != "" {
		lines, err := reader.ReadRawFile(cfg.ResolverFile)
		if err != nil {
			return nil, fmt.Errorf("read resolver file: %w", err)
		}
		raw = append(raw, lines...)
	}
	if cfg.ResolverList != "" {
		raw = append(raw, strings.Split(cfg.ResolverList, ",")...)
	}
	if len(raw) == 0 {
		raw = append(raw, defaultResolvers...)
	}

	seen := make(map[string]bool)
	resolvers := make([]string, 0, len(raw))
	for _, item := range raw {
		normalized, err := dns.NormalizeResolver(item)
		if err != nil {
			return nil, err
		}
		if !seen[normalized] {
			seen[normalized] = true
			resolvers = append(resolvers, normalized)
		}
	}
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("no valid resolvers configured")
	}
	return resolvers, nil
}

func prepareInput(cfg *config.Config, stdin io.Reader) (io.Reader, func(), int64, error) {
	var inputs []io.Reader
	var files []*os.File
	var total int64
	knownTotal := true

	if cfg.TargetList != "" && cfg.TargetList != "-" {
		if !cfg.Stream {
			report, err := reader.CountFile(cfg.TargetList, true)
			if err != nil {
				return nil, func() {}, 0, err
			}
			total += report.Emitted
		} else {
			knownTotal = false
		}
		file, err := os.Open(cfg.TargetList)
		if err != nil {
			return nil, func() {}, 0, err
		}
		files = append(files, file)
		inputs = append(inputs, file)
	} else if cfg.TargetList == "-" || len(cfg.Targets) == 0 {
		inputs = append(inputs, stdin)
		knownTotal = false
	}

	if len(cfg.Targets) > 0 {
		direct := strings.Join(cfg.Targets, "\n") + "\n"
		inputs = append(inputs, strings.NewReader(direct))
		if len(inputs) == 1 && !cfg.Stream {
			report, err := reader.CountTargets(strings.NewReader(direct), true)
			if err != nil {
				return nil, func() {}, 0, err
			}
			total += report.Emitted
		} else if len(inputs) > 1 {
			knownTotal = false
		}
	}
	if len(inputs) == 0 {
		return nil, func() {}, 0, fmt.Errorf("no input source")
	}
	closeFiles := func() {
		for _, file := range files {
			_ = file.Close()
		}
	}
	if !knownTotal {
		total = 0
	}
	return io.MultiReader(inputs...), closeFiles, total, nil
}

func configureColor(terminal bool, output io.Writer, cfg *config.Config) {
	_ = output
	if cfg == nil || cfg.NoColor || os.Getenv("NO_COLOR") != "" || !terminal {
		ui.DisableColors()
	}
}

func isTerminal(value any) bool {
	file, ok := value.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
