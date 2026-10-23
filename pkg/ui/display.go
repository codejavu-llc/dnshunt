package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/codejavu-llc/dnshunt/pkg/dns"
)

func PrintBanner(output io.Writer) {
	banner := CBCyan + `
   ██████╗ ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
   ██╔══██╗████╗  ██║██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
   ██║  ██║██╔██╗ ██║███████╗███████║██║   ██║██╔██╗ ██║   ██║
   ██║  ██║██║╚██╗██║╚════██║██╔══██║██║   ██║██║╚██╗██║   ██║
   ██████╔╝██║ ╚████║███████║██║  ██║╚██████╔╝██║ ╚████║   ██║
   ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝` + CReset + `
` + CBMag + `       Fast, consensus-aware DNS reconnaissance` + CReset + `
` + CDim + `   ─────────────────────────────────────────────────────` + CReset
	fmt.Fprintln(output, banner)
}

func PrintHelp(output io.Writer) {
	PrintBanner(output)
	fmt.Fprintf(output, `%sUSAGE:%s
  dnshunt [options] [target ...]
  cat targets.txt | dnshunt [options]

%sINPUT:%s
  -l, -list <file>          Target file (stdin is used when omitted)
  -r, -resolvers <file>     Resolver file, one endpoint per line
  -R <list>                 Comma-separated resolver endpoints

%sQUERY:%s
  -t, -type <types>         Comma-separated record types (default A)
  -all                      A, AAAA, CNAME, NS, MX, TXT, SRV, SOA,
                            CAA, HTTPS, SVCB, DS, and DNSKEY
  -c, -threads <n>          Concurrent target/type jobs (default 100)
  -rc <n>                   Maximum resolvers per job (default 5)
  -consensus <n>            Required agreeing resolvers (default 1)
  -retry <n>                Attempts on network/SERVFAIL/REFUSED (default 2)
  -timeout <duration>       Per-attempt timeout: 3s or legacy 3000ms
  -rate-limit <qps>         Global wire-query rate limit (default unlimited)
  -tcp                      Force TCP; UDP already falls back on truncation
  -edns-size <bytes>        Advertised UDP payload size (default 1400)

%sWILDCARD FILTER:%s
  -wildcard-domain <name>   Probe and filter wildcard answers below a domain
  -wildcard-tests <n>       Random probes for load-balanced wildcards (default 3)
  -include-wildcards        Keep matching wildcard results

%sOUTPUT:%s
  -o <file>                 Save results to a file (CLI results require -v)
  -format <name>            plain, text, jsonl, or json
  -jsonl                    Shortcut for -format jsonl
  -silent                   Print names only (successes by default)
  -include-failures         Include failed lookups alongside successes
  -v, -verbose              Show CLI results with -o; details in text output
  -stats                    Print a final summary even outside a terminal
  -stream                   Constant-memory mode (disables input dedup/count)
  -nc, -no-color            Disable ANSI colors
  -no-progress              Disable live progress
  -version                  Show version
  -h, -help                 Show help

%sRESOLVER ENDPOINTS:%s
  1.1.1.1  [2606:4700:4700::1111]:53  udp://host:53
  tcp://host:53  tls://dns.example:853  https://dns.example/dns-query

%sEXAMPLES:%s
  subfinder -silent -d example.com | dnshunt -silent -consensus 2
  dnshunt -l hosts.txt -t A,AAAA,CNAME -jsonl -o results.jsonl
  dnshunt -l candidates.txt -wildcard-domain example.com -silent
  dnshunt example.com -all -R tls://1dot1dot1dot1.cloudflare-dns.com
`, CBold+CBGreen, CReset, CBold+CBGreen, CReset, CBold+CBGreen, CReset,
		CBold+CBGreen, CReset, CBold+CBGreen, CReset, CBold+CBGreen, CReset,
		CBold+CBGreen, CReset)
}

func PrintSummary(output io.Writer, stats *dns.Stats, invalid, duplicates int64) {
	processed, success, failed, wildcards, queries, _ := stats.GetCounts()
	elapsed := stats.ElapsedSeconds()
	fmt.Fprintf(output, "\n%sSummary%s  %d processed · %s%d resolved%s · %s%d failed%s",
		CBold, CReset, processed, CBGreen, success, CReset, CBRed, failed, CReset)
	if wildcards > 0 {
		fmt.Fprintf(output, " · %s%d wildcard%s", CBYellow, wildcards, CReset)
	}
	if invalid > 0 || duplicates > 0 {
		fmt.Fprintf(output, " · %d invalid · %d duplicate", invalid, duplicates)
	}
	fmt.Fprintf(output, " · %d queries · %s\n", queries, FormatDuration(elapsed))
	if elapsed > 0 {
		fmt.Fprintf(output, "%sThroughput%s  %.1f results/s · %.1f DNS queries/s\n", CDim, CReset, float64(processed)/elapsed, float64(queries)/elapsed)
	}
}

func SupportedTypes() string {
	return strings.Join([]string{"A", "AAAA", "CNAME", "NS", "MX", "TXT", "SRV", "PTR", "SOA", "CAA", "HTTPS", "SVCB", "TLSA", "DS", "DNSKEY", "NAPTR", "SSHFP", "CERT", "ANY"}, ", ")
}
