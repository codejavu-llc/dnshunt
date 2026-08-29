package config

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	dnspkg "github.com/codejavu-llc/dnshunt/pkg/dns"
	"github.com/spf13/pflag"
)

var ErrHelp = errors.New("help requested")

type Config struct {
	ResolverFile    string
	ResolverList    string
	TargetList      string
	Targets         []string
	RecordTypes     []string
	QTypes          []uint16
	Concurrency     int
	Timeout         time.Duration
	UseTCP          bool
	OutputFile      string
	OutputFormat    string
	ResolversEach   int
	Retries         int
	Consensus       int
	RateLimit       int
	EDNSSize        uint
	Stream          bool
	Silent          bool
	Verbose         bool
	Stats           bool
	NoColor         bool
	NoProgress      bool
	IncludeFailures bool
	JSONL           bool
	WildcardDomain  string
	WildcardTests   int
	IncludeWildcard bool
	ShowVersion     bool
}

type durationValue struct{ value *time.Duration }

func (d durationValue) String() string {
	if d.value == nil {
		return ""
	}
	return d.value.String()
}

func (d durationValue) Set(raw string) error {
	if milliseconds, err := strconv.Atoi(raw); err == nil {
		*d.value = time.Duration(milliseconds) * time.Millisecond
		return nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("use a duration such as 3s or milliseconds such as 3000: %w", err)
	}
	*d.value = parsed
	return nil
}

func (d durationValue) Type() string { return "duration" }

// Parse parses command-line arguments without exiting the process, which keeps
// the CLI embeddable and straightforward to test.
func Parse(args []string, stderr io.Writer) (*Config, error) {
	cfg := &Config{
		Concurrency:   100,
		Timeout:       3 * time.Second,
		ResolversEach: 5,
		Retries:       2,
		Consensus:     1,
		EDNSSize:      1400,
		WildcardTests: 3,
	}

	fs := pflag.NewFlagSet("dnshunt", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	var recordTypes string
	var allRecords bool
	var help bool

	fs.StringVarP(&cfg.ResolverFile, "resolvers", "r", "", "resolver file")
	fs.StringVarP(&cfg.ResolverList, "resolver", "R", "", "comma-separated resolvers")
	fs.StringVarP(&cfg.TargetList, "list", "l", "", "target list")
	fs.StringVarP(&recordTypes, "type", "t", "A", "record types")
	fs.BoolVar(&allRecords, "all", false, "query the recon record set")
	fs.IntVarP(&cfg.Concurrency, "threads", "c", cfg.Concurrency, "concurrent targets")
	fs.Var(durationValue{&cfg.Timeout}, "timeout", "query timeout")
	fs.IntVar(&cfg.ResolversEach, "rc", cfg.ResolversEach, "resolvers per target")
	fs.IntVar(&cfg.Retries, "retry", cfg.Retries, "query attempts")
	fs.IntVar(&cfg.Retries, "retries", cfg.Retries, "query attempts")
	fs.IntVar(&cfg.Consensus, "consensus", cfg.Consensus, "minimum agreeing resolvers")
	fs.IntVar(&cfg.RateLimit, "rate-limit", 0, "maximum DNS queries per second")
	fs.IntVar(&cfg.RateLimit, "rl", 0, "maximum DNS queries per second")
	fs.UintVar(&cfg.EDNSSize, "edns-size", cfg.EDNSSize, "advertised UDP payload size")
	fs.BoolVar(&cfg.UseTCP, "tcp", false, "use TCP")
	fs.BoolVar(&cfg.Stream, "stream", false, "constant-memory input mode")
	fs.BoolVar(&cfg.Silent, "silent", false, "print only resolved names")
	fs.BoolVarP(&cfg.Verbose, "verbose", "v", false, "include resolver details in text output")
	fs.BoolVar(&cfg.Stats, "stats", false, "print a final summary")
	fs.BoolVar(&cfg.NoColor, "no-color", false, "disable ANSI colors")
	fs.BoolVar(&cfg.NoColor, "nc", false, "disable ANSI colors")
	fs.BoolVar(&cfg.NoProgress, "no-progress", false, "disable live progress")
	fs.BoolVar(&cfg.IncludeFailures, "include-failures", false, "emit failed lookups")
	fs.StringVarP(&cfg.OutputFile, "output", "o", "", "output file")
	fs.StringVar(&cfg.OutputFormat, "format", "", "plain, text, jsonl, or json")
	fs.BoolVarP(&cfg.JSONL, "jsonl", "j", false, "write newline-delimited JSON")
	fs.StringVar(&cfg.WildcardDomain, "wildcard-domain", "", "filter wildcard answers below this domain")
	fs.IntVar(&cfg.WildcardTests, "wildcard-tests", cfg.WildcardTests, "random wildcard probes")
	fs.BoolVar(&cfg.IncludeWildcard, "include-wildcards", false, "emit wildcard matches as successful")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "show version")
	fs.BoolVarP(&help, "help", "h", false, "show help")

	if err := fs.Parse(normalizeLegacyFlags(args)); err != nil {
		return nil, err
	}
	if help {
		return nil, ErrHelp
	}
	cfg.Targets = fs.Args()

	if allRecords {
		recordTypes = "A,AAAA,CNAME,NS,MX,TXT,SRV,SOA,CAA,HTTPS,SVCB,DS,DNSKEY"
	}
	var err error
	cfg.RecordTypes, cfg.QTypes, err = dnspkg.ParseRecordTypes(recordTypes)
	if err != nil {
		return nil, err
	}

	if cfg.Concurrency < 1 || cfg.Concurrency > 100000 {
		return nil, fmt.Errorf("concurrency must be between 1 and 100000")
	}
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be greater than zero")
	}
	if cfg.ResolversEach < 1 {
		return nil, fmt.Errorf("resolvers per target must be at least 1")
	}
	if cfg.Retries < 1 || cfg.Retries > 20 {
		return nil, fmt.Errorf("retry must be between 1 and 20")
	}
	if cfg.Consensus < 1 || cfg.Consensus > cfg.ResolversEach {
		return nil, fmt.Errorf("consensus must be between 1 and the resolvers-per-target value (%d)", cfg.ResolversEach)
	}
	if cfg.RateLimit < 0 || cfg.RateLimit > 1000000 {
		return nil, fmt.Errorf("rate-limit must be between 0 and 1000000")
	}
	if cfg.EDNSSize < 512 || cfg.EDNSSize > 4096 {
		return nil, fmt.Errorf("edns-size must be between 512 and 4096")
	}
	if cfg.WildcardTests < 1 || cfg.WildcardTests > 100 {
		return nil, fmt.Errorf("wildcard-tests must be between 1 and 100")
	}

	if cfg.JSONL {
		if cfg.OutputFormat != "" && !strings.EqualFold(cfg.OutputFormat, "jsonl") {
			return nil, fmt.Errorf("-jsonl conflicts with -format %s", cfg.OutputFormat)
		}
		cfg.OutputFormat = "jsonl"
	}
	if cfg.OutputFormat == "" {
		cfg.OutputFormat = inferFormat(cfg.OutputFile)
	}
	cfg.OutputFormat = strings.ToLower(cfg.OutputFormat)
	switch cfg.OutputFormat {
	case "plain", "text", "jsonl", "json":
	default:
		return nil, fmt.Errorf("unsupported output format %q (use plain, text, jsonl, or json)", cfg.OutputFormat)
	}

	return cfg, nil
}

// pflag enables options after positional arguments but reserves one-dash forms
// for one-letter shorthands. Preserve dnshunt's original -timeout/-rc style by
// normalizing known legacy names to their standard double-dash forms.
func normalizeLegacyFlags(args []string) []string {
	longNames := map[string]bool{
		"resolvers": true, "resolver": true, "list": true, "type": true, "all": true,
		"threads": true, "timeout": true, "rc": true, "retry": true, "retries": true,
		"consensus": true, "rate-limit": true, "rl": true, "edns-size": true, "tcp": true,
		"stream": true, "silent": true, "verbose": true, "stats": true, "no-color": true,
		"nc": true, "no-progress": true, "include-failures": true, "output": true,
		"format": true, "jsonl": true, "wildcard-domain": true, "wildcard-tests": true,
		"include-wildcards": true, "version": true, "help": true,
	}
	normalized := append([]string(nil), args...)
	for index, argument := range normalized {
		if !strings.HasPrefix(argument, "-") || strings.HasPrefix(argument, "--") || len(argument) < 3 {
			continue
		}
		name := strings.TrimPrefix(argument, "-")
		if equals := strings.IndexByte(name, '='); equals >= 0 {
			name = name[:equals]
		}
		if longNames[name] {
			normalized[index] = "-" + argument
		}
	}
	return normalized
}

func inferFormat(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".jsonl"), strings.HasSuffix(lower, ".ndjson"):
		return "jsonl"
	case strings.HasSuffix(lower, ".json"):
		return "json"
	case strings.HasSuffix(lower, ".txt"):
		return "text"
	default:
		return "plain"
	}
}
