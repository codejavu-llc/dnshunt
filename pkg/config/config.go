package config

import (
	"flag"
	"fmt"
	"os"

	"dnshunt/pkg/dns"
	"dnshunt/pkg/ui"
)

type Config struct {
	ResolverFile  string
	ResolverList  string
	TargetList    string
	RecordType    string
	Concurrency   int
	TimeoutMs     int
	UseTCP        bool
	Verbose       bool
	OutputFile    string
	ResolversEach int
	QType         uint16
}

func Parse() (*Config, bool) {
	cfg := &Config{}
	flag.StringVar(&cfg.ResolverFile, "r", "", "")
	flag.StringVar(&cfg.ResolverList, "R", "", "")
	flag.StringVar(&cfg.TargetList, "l", "", "")
	flag.StringVar(&cfg.RecordType, "t", "A", "")
	flag.IntVar(&cfg.Concurrency, "c", 100, "")
	flag.IntVar(&cfg.TimeoutMs, "timeout", 3000, "")
	flag.IntVar(&cfg.ResolversEach, "rc", 5, "")
	flag.BoolVar(&cfg.UseTCP, "tcp", false, "")
	flag.BoolVar(&cfg.Verbose, "v", false, "")
	flag.StringVar(&cfg.OutputFile, "o", "", "")
	help := flag.Bool("h", false, "")
	helpLong := flag.Bool("help", false, "")

	flag.Usage = ui.PrintHelp
	flag.Parse()

	if *help || *helpLong {
		ui.PrintHelp()
		return nil, false
	}

	if cfg.TargetList == "" {
		fmt.Fprintf(os.Stderr, "%s[!]%s -l (target list) is required. Use -h for help.\n", ui.CBRed, ui.CReset)
		os.Exit(1)
	}

	qtype, err := dns.RecordTypeFromString(cfg.RecordType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[!]%s %v\n", ui.CBRed, ui.CReset, err)
		os.Exit(1)
	}
	cfg.QType = qtype

	return cfg, true
}