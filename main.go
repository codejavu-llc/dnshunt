package main

// ╔══════════════════════════════════════════════════════════════════╗
// ║                                                                  ║
// ║   ██████╗ ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗ ║
// ║   ██╔══██╗████╗  ██║██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝ ║
// ║   ██║  ██║██╔██╗ ██║███████╗███████║██║   ██║██╔██╗ ██║   ██║    ║
// ║   ██║  ██║██║╚██╗██║╚════██║██╔══██║██║   ██║██║╚██╗██║   ██║    ║
// ║   ██████╔╝██║ ╚████║███████║██║  ██║╚██████╔╝██║ ╚████║   ██║    ║
// ║   ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ║
// ║                                                                  ║
// ║                  Made with ♥ by CodejaVu Team                    ║
// ╚══════════════════════════════════════════════════════════════════╝

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// ══════════════════════════════════════════════════════════════════
// ANSI color codes — pure escape sequences, no external libs
// ══════════════════════════════════════════════════════════════════
const (
	cReset   = "\033[0m"
	cBold    = "\033[1m"
	cDim     = "\033[2m"
	cRed     = "\033[31m"
	cGreen   = "\033[32m"
	cYellow  = "\033[33m"
	cBlue    = "\033[34m"
	cMagenta = "\033[35m"
	cCyan    = "\033[36m"
	cWhite   = "\033[37m"
	cBRed    = "\033[91m"
	cBGreen  = "\033[92m"
	cBYellow = "\033[93m"
	cBBlue   = "\033[94m"
	cBMag    = "\033[95m"
	cBCyan   = "\033[96m"
)

// ══════════════════════════════════════════════════════════════════
// Configuration
// ══════════════════════════════════════════════════════════════════
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
	qtype         uint16 // resolved from RecordType, set in main
}

// ══════════════════════════════════════════════════════════════════
// A single resolution result for one target
// ══════════════════════════════════════════════════════════════════
type Result struct {
	Target     string             `json:"target"`
	RecordType string             `json:"record_type"`
	Answers    []string           `json:"answers"`
	Errors     []string           `json:"errors,omitempty"`
	Resolvers  []ResolverResponse `json:"resolvers"`
	Success    bool               `json:"success"`
	Timestamp  string             `json:"timestamp"`
}

type ResolverResponse struct {
	Resolver string   `json:"resolver"`
	Answers  []string `json:"answers,omitempty"`
	Error    string   `json:"error,omitempty"`
	RTTms    int64    `json:"rtt_ms"`
}

// ══════════════════════════════════════════════════════════════════
// Global counters for live progress
// ══════════════════════════════════════════════════════════════════
var (
	totalTargets   int64
	processedCount int64
	successCount   int64
	failureCount   int64
	startTime      time.Time
)

// ══════════════════════════════════════════════════════════════════
// Banner
// ══════════════════════════════════════════════════════════════════
func printBanner() {
	banner := cBCyan + `
   ██████╗ ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
   ██╔══██╗████╗  ██║██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
   ██║  ██║██╔██╗ ██║███████╗███████║██║   ██║██╔██╗ ██║   ██║   
   ██║  ██║██║╚██╗██║╚════██║██╔══██║██║   ██║██║╚██╗██║   ██║   
   ██████╔╝██║ ╚████║███████║██║  ██║╚██████╔╝██║ ╚████║   ██║   
   ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ` + cReset + `
` + cBMag + `         ⚡ Fast Concurrent DNS Resolver ⚡` + cReset + `
` + cBYellow + `              Made with ♥ by CodejaVu Team` + cReset + `
` + cDim + `   ─────────────────────────────────────────────────────` + cReset + `
`
	fmt.Println(banner)
}

// ══════════════════════════════════════════════════════════════════
// Help
// ══════════════════════════════════════════════════════════════════
func printHelp() {
	printBanner()
	fmt.Printf("%sUSAGE:%s\n", cBold+cBGreen, cReset)
	fmt.Printf("  dnshunt [options]\n\n")

	fmt.Printf("%sOPTIONS:%s\n", cBold+cBGreen, cReset)
	opts := [][]string{
		{"-r", "<file>", "File containing DNS resolver IPs (one per line)"},
		{"-R", "<list>", "Single or multiple resolver IPs (e.g. 1.1.1.1,8.8.8.8)"},
		{"-l", "<file>", "Target list (subdomains/domains/IPs/hostnames)"},
		{"-t", "<type>", "DNS record type: A, AAAA, CNAME, TXT, MX, PTR, CAA, NS, SOA"},
		{"-c", "<int>", "Concurrency level (default: 100)"},
		{"-timeout", "<ms>", "Query timeout in milliseconds (default: 3000)"},
		{"-rc", "<int>", "Number of resolvers per target (default: 5)"},
		{"-tcp", "", "Use TCP instead of UDP for queries"},
		{"-v", "", "Verbose output"},
		{"-o", "<file>", "Output file (auto-detects .json or .txt)"},
		{"-h", "", "Show this help message"},
	}
	for _, o := range opts {
		fmt.Printf("  %s%-10s%s %s%-10s%s %s\n",
			cBCyan, o[0], cReset,
			cYellow, o[1], cReset,
			o[2])
	}

	fmt.Printf("\n%sEXAMPLES:%s\n", cBold+cBGreen, cReset)
	fmt.Printf("  %s# Basic A record resolution%s\n", cDim, cReset)
	fmt.Printf("  dnshunt -l domains.txt -R 1.1.1.1,8.8.8.8 -t A\n\n")
	fmt.Printf("  %s# Use a resolver file with high concurrency%s\n", cDim, cReset)
	fmt.Printf("  dnshunt -l targets.txt -r resolvers.txt -t TXT -c 500 -o results.json\n\n")
	fmt.Printf("  %s# TCP queries with 7 resolvers per target%s\n", cDim, cReset)
	fmt.Printf("  dnshunt -l hosts.txt -R 8.8.8.8 -t MX -tcp -rc 7 -v\n\n")

	fmt.Printf("%s%s\n", cDim, strings.Repeat("─", 60))
	fmt.Printf("              Made by CodejaVu Team%s\n\n", cReset)
}

// ══════════════════════════════════════════════════════════════════
// File loaders
// ══════════════════════════════════════════════════════════════════
func loadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := cleanLine(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}

// cleanLine strips not just standard whitespace but also UTF-8 BOM,
// zero-width characters, and any trailing dot — common sources of
// "domain looks fine but query fails" bugs when files come from
// Windows editors, copy-pasted from the web, or piped through tools
// that add stray bytes.
func cleanLine(s string) string {
	s = strings.TrimPrefix(s, "\uFEFF") // UTF-8 BOM
	// Strip zero-width / invisible characters anywhere in the line.
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF':
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".") // trailing dot is normalized later
	return s
}

// ══════════════════════════════════════════════════════════════════
// Resolver normalization — accept "1.1.1.1" or "1.1.1.1:53"
// ══════════════════════════════════════════════════════════════════
func normalizeResolver(r string) string {
	r = strings.TrimSpace(r)
	if r == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(r); err == nil {
		return r
	}
	return r + ":53"
}

// ══════════════════════════════════════════════════════════════════
// Record type mapping
// ══════════════════════════════════════════════════════════════════
// recordTypeFromString maps user-facing names to dns.Type* constants.
func recordTypeFromString(t string) (uint16, error) {
	switch strings.ToUpper(t) {
	case "A":
		return dns.TypeA, nil
	case "AAAA":
		return dns.TypeAAAA, nil
	case "CNAME":
		return dns.TypeCNAME, nil
	case "TXT":
		return dns.TypeTXT, nil
	case "MX":
		return dns.TypeMX, nil
	case "PTR":
		return dns.TypePTR, nil
	case "CAA":
		return dns.TypeCAA, nil
	case "NS":
		return dns.TypeNS, nil
	case "SOA":
		return dns.TypeSOA, nil
	default:
		return 0, fmt.Errorf("unsupported record type: %s", t)
	}
}

// shouldAutoTCP reports whether a record type is known to commonly produce
// responses too large for legacy 512-byte UDP. For these we use TCP from
// the start instead of paying the cost of a UDP query that gets truncated
// and retried. The user can still force TCP for everything with -tcp.
func shouldAutoTCP(qtype uint16) bool {
	switch qtype {
	case dns.TypeTXT, dns.TypeMX, dns.TypeCAA, dns.TypeSOA:
		// TXT — DKIM/DMARC/SPF/verification tokens are routinely >512B.
		// MX — large mail provider domains list many MX hosts.
		// CAA — issuewild + iodef URIs run long.
		// SOA — usually small, but bundled with NSEC/RRSIG for DNSSEC zones.
		return true
	}
	return false
}

// Convert an IP into its in-addr.arpa / ip6.arpa form for PTR lookups
func toReverse(target string) string {
	if r, err := dns.ReverseAddr(target); err == nil {
		return r
	}
	return target
}

// ══════════════════════════════════════════════════════════════════
// Format an answer record into a clean human string
// ══════════════════════════════════════════════════════════════════
func formatAnswer(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return strings.TrimSuffix(v.Target, ".")
	case *dns.TXT:
		return strings.Join(v.Txt, " ")
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, "."))
	case *dns.PTR:
		return strings.TrimSuffix(v.Ptr, ".")
	case *dns.CAA:
		return fmt.Sprintf("%d %s \"%s\"", v.Flag, v.Tag, v.Value)
	case *dns.NS:
		return strings.TrimSuffix(v.Ns, ".")
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			strings.TrimSuffix(v.Ns, "."),
			strings.TrimSuffix(v.Mbox, "."),
			v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	default:
		return rr.String()
	}
}

// ══════════════════════════════════════════════════════════════════
// Single DNS query against one resolver
// ══════════════════════════════════════════════════════════════════
func queryResolver(ctx context.Context, target string, qtype uint16, resolver string, useTCP bool, timeout time.Duration) ResolverResponse {
	resp := ResolverResponse{Resolver: resolver}

	// Auto-promote certain record types to TCP unless the user already asked
	// for TCP globally. This sidesteps the 512-byte UDP truncation problem
	// for record types where large responses are the norm rather than the
	// exception (TXT, MX, CAA, SOA).
	effectiveTCP := useTCP || shouldAutoTCP(qtype)

	c := &dns.Client{Timeout: timeout}
	if effectiveTCP {
		c.Net = "tcp"
	} else {
		c.Net = "udp"
		// Match the EDNS0 buffer we advertise below — otherwise the
		// library's local read buffer can clip large UDP responses
		// even when the resolver returned them in full.
		c.UDPSize = 4096
	}

	// PTR queries need reverse-DNS form
	queryName := target
	if qtype == dns.TypePTR {
		queryName = toReverse(target)
	}
	if !strings.HasSuffix(queryName, ".") {
		queryName = queryName + "."
	}

	m := new(dns.Msg)
	m.SetQuestion(queryName, qtype)
	m.RecursionDesired = true
	// Advertise EDNS0 so the resolver can return responses larger than
	// the legacy 512-byte UDP limit. Without this, large TXT/MX/CAA
	// answers get silently truncated and look like "no answer."
	m.SetEdns0(4096, false)

	start := time.Now()
	in, _, err := c.ExchangeContext(ctx, m, resolver)
	resp.RTTms = time.Since(start).Milliseconds()

	if err != nil {
		resp.Error = err.Error()
		return resp
	}

	// Belt-and-braces: if we still ended up on UDP (record type not in the
	// auto-TCP list, user didn't pass -tcp) and the response came back
	// truncated, retry over TCP. RFC 5966 requires this fallback.
	if in != nil && in.Truncated && !effectiveTCP {
		tcpClient := &dns.Client{Net: "tcp", Timeout: timeout}
		tcpStart := time.Now()
		in2, _, err2 := tcpClient.ExchangeContext(ctx, m, resolver)
		resp.RTTms += time.Since(tcpStart).Milliseconds()
		if err2 == nil && in2 != nil {
			in = in2
		}
		// If the TCP retry failed, fall through and use whatever the
		// truncated UDP response gave us — better than nothing.
	}

	if in.Rcode != dns.RcodeSuccess {
		resp.Error = fmt.Sprintf("rcode=%s", dns.RcodeToString[in.Rcode])
		return resp
	}

	for _, rr := range in.Answer {
		resp.Answers = append(resp.Answers, formatAnswer(rr))
	}
	// SOA responses often live in the Ns section instead of Answer
	if qtype == dns.TypeSOA && len(resp.Answers) == 0 {
		for _, rr := range in.Ns {
			if _, ok := rr.(*dns.SOA); ok {
				resp.Answers = append(resp.Answers, formatAnswer(rr))
			}
		}
	}

	return resp
}

// ══════════════════════════════════════════════════════════════════
// Resolve one target across N random resolvers
// ══════════════════════════════════════════════════════════════════
func resolveTarget(ctx context.Context, target string, qtype uint16, qtypeStr string, resolvers []string, n int, useTCP bool, timeout time.Duration) Result {
	res := Result{
		Target:     target,
		RecordType: qtypeStr,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	// Pick n unique resolvers (or fewer if pool is small)
	picked := pickResolvers(resolvers, n)

	answerSet := make(map[string]struct{})
	noerrorEmpty := 0
	for _, r := range picked {
		rr := queryResolver(ctx, target, qtype, r, useTCP, timeout)
		res.Resolvers = append(res.Resolvers, rr)
		if rr.Error != "" {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %s", r, rr.Error))
			continue
		}
		if len(rr.Answers) == 0 {
			noerrorEmpty++
			continue
		}
		for _, a := range rr.Answers {
			answerSet[a] = struct{}{}
		}
	}

	for a := range answerSet {
		res.Answers = append(res.Answers, a)
	}
	res.Success = len(res.Answers) > 0
	// If we got nothing back but the resolvers all said NOERROR, surface that
	// distinctly so the user can tell "domain has no record of this type" apart
	// from "everything timed out / NXDOMAIN / refused."
	if !res.Success && noerrorEmpty > 0 && len(res.Errors) == 0 {
		res.Errors = append(res.Errors,
			fmt.Sprintf("NOERROR/empty from %d resolver(s) — no %s record exists for this name",
				noerrorEmpty, qtypeStr))
	}
	return res
}

func pickResolvers(pool []string, n int) []string {
	if n >= len(pool) {
		out := make([]string, len(pool))
		copy(out, pool)
		return out
	}
	idx := rand.Perm(len(pool))[:n]
	out := make([]string, 0, n)
	for _, i := range idx {
		out = append(out, pool[i])
	}
	return out
}

// ══════════════════════════════════════════════════════════════════
// Live progress bar — printed in-place using \r
// ══════════════════════════════════════════════════════════════════
func progressTicker(ctx context.Context, done chan struct{}) {
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()
	defer close(done)

	render := func() {
		total := atomic.LoadInt64(&totalTargets)
		proc := atomic.LoadInt64(&processedCount)
		ok := atomic.LoadInt64(&successCount)
		fail := atomic.LoadInt64(&failureCount)
		left := total - proc

		var pct float64
		if total > 0 {
			pct = float64(proc) / float64(total) * 100
		}

		elapsed := time.Since(startTime).Seconds()
		var rate float64
		if elapsed > 0 {
			rate = float64(proc) / elapsed
		}
		var eta string
		if rate > 0 && left > 0 {
			etaSecs := float64(left) / rate
			eta = formatDuration(time.Duration(etaSecs * float64(time.Second)))
		} else {
			eta = "--"
		}

		bar := renderBar(pct, 28)

		line := fmt.Sprintf("\r%s[%s%s%s] %s%5.1f%%%s  %s%d%s/%s%d%s  %s✓ %d%s  %s✗ %d%s  %sleft: %d%s  %s%.0f q/s%s  %sETA %s%s   ",
			cDim, cReset, bar, cReset,
			cBYellow, pct, cReset,
			cBCyan, proc, cReset,
			cBold, total, cReset,
			cBGreen, ok, cReset,
			cBRed, fail, cReset,
			cBMag, left, cReset,
			cBBlue, rate, cReset,
			cBYellow, eta, cReset,
		)
		fmt.Fprint(os.Stderr, line)
	}

	for {
		select {
		case <-ctx.Done():
			render()
			fmt.Fprintln(os.Stderr)
			return
		case <-ticker.C:
			render()
		}
	}
}

func renderBar(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	return cBGreen + strings.Repeat("█", filled) + cDim + strings.Repeat("░", width-filled) + cReset
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

// ══════════════════════════════════════════════════════════════════
// Verbose per-result printer.
//
// Without -v, this is a no-op — the user sees only the live progress
// bar and the final summary. The full results are still collected and
// written to the output file if -o was passed.
// ══════════════════════════════════════════════════════════════════
func printResultLive(res Result, verbose bool) {
	if !verbose {
		return
	}

	// Clear current progress line first so our line isn't overwritten
	// by the next progress tick.
	fmt.Fprint(os.Stderr, "\r\033[K")

	if res.Success {
		fmt.Printf("%s[+]%s %s%-40s%s %s→%s %s%s%s\n",
			cBGreen, cReset,
			cBold, res.Target, cReset,
			cDim, cReset,
			cBCyan, strings.Join(res.Answers, ", "), cReset,
		)
		for _, rr := range res.Resolvers {
			if rr.Error != "" {
				fmt.Printf("    %s└─%s %s%-22s%s %s%s%s\n",
					cDim, cReset,
					cYellow, rr.Resolver, cReset,
					cRed, rr.Error, cReset)
			} else {
				fmt.Printf("    %s└─%s %s%-22s%s %s[%dms]%s %s%s%s\n",
					cDim, cReset,
					cYellow, rr.Resolver, cReset,
					cBlue, rr.RTTms, cReset,
					cGreen, strings.Join(rr.Answers, ", "), cReset)
			}
		}
	} else {
		reason := "no answer"
		if len(res.Errors) > 0 {
			reason = res.Errors[0]
		}
		fmt.Printf("%s[-]%s %s%-40s%s %s(%s)%s\n",
			cBRed, cReset,
			cDim, res.Target, cReset,
			cRed, reason, cReset)
	}
}

// ══════════════════════════════════════════════════════════════════
// Output writers
// ══════════════════════════════════════════════════════════════════
func writeOutput(path string, results []Result, cfg *Config) error {
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		return writeJSON(path, results, cfg)
	}
	return writeText(path, results, cfg)
}

func writeJSON(path string, results []Result, cfg *Config) error {
	out := map[string]interface{}{
		"meta": map[string]interface{}{
			"tool":            "dnshunt",
			"author":          "CodejaVu Team",
			"timestamp":       time.Now().UTC().Format(time.RFC3339),
			"record_type":     cfg.RecordType,
			"total_targets":   len(results),
			"resolvers_each":  cfg.ResolversEach,
			"protocol":        effectiveProtoLabel(cfg, cfg.qtype),
			"timeout_ms":      cfg.TimeoutMs,
		},
		"results": results,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeText(path string, results []Result, cfg *Config) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()

	var ok, fail int
	for _, r := range results {
		if r.Success {
			ok++
		} else {
			fail++
		}
	}

	border := strings.Repeat("═", 72)
	fmt.Fprintf(w, "╔%s╗\n", border)
	fmt.Fprintf(w, "║%s║\n", centerPad("DNSHUNT — DNS Resolution Report", 72))
	fmt.Fprintf(w, "║%s║\n", centerPad("Made by CodejaVu Team", 72))
	fmt.Fprintf(w, "╚%s╝\n\n", border)

	fmt.Fprintf(w, "Generated:       %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "Record type:     %s\n", cfg.RecordType)
	fmt.Fprintf(w, "Protocol:        %s\n", effectiveProtoLabel(cfg, cfg.qtype))
	fmt.Fprintf(w, "Timeout:         %dms\n", cfg.TimeoutMs)
	fmt.Fprintf(w, "Resolvers each:  %d\n", cfg.ResolversEach)
	fmt.Fprintf(w, "Concurrency:     %d\n", cfg.Concurrency)
	fmt.Fprintf(w, "Total targets:   %d\n", len(results))
	fmt.Fprintf(w, "Resolved:        %d\n", ok)
	fmt.Fprintf(w, "Failed:          %d\n", fail)
	fmt.Fprintf(w, "\n%s\n\n", strings.Repeat("─", 72))

	// Successful results
	fmt.Fprintf(w, "▶ RESOLVED (%d)\n%s\n\n", ok, strings.Repeat("─", 72))
	for _, r := range results {
		if !r.Success {
			continue
		}
		fmt.Fprintf(w, "[+] %s\n", r.Target)
		for _, ans := range r.Answers {
			fmt.Fprintf(w, "      ├─ %s\n", ans)
		}
		if cfg.Verbose {
			for _, rr := range r.Resolvers {
				if rr.Error != "" {
					fmt.Fprintf(w, "      ·  via %-22s ERROR: %s\n", rr.Resolver, rr.Error)
				} else {
					fmt.Fprintf(w, "      ·  via %-22s [%dms] %s\n", rr.Resolver, rr.RTTms, strings.Join(rr.Answers, ", "))
				}
			}
		}
		fmt.Fprintln(w)
	}

	// Failed
	if fail > 0 {
		fmt.Fprintf(w, "\n▶ FAILED (%d)\n%s\n\n", fail, strings.Repeat("─", 72))
		for _, r := range results {
			if r.Success {
				continue
			}
			reason := "no answer"
			if len(r.Errors) > 0 {
				reason = r.Errors[0]
			}
			fmt.Fprintf(w, "[-] %-40s  (%s)\n", r.Target, reason)
		}
	}

	fmt.Fprintf(w, "\n%s\n", strings.Repeat("═", 72))
	fmt.Fprintf(w, "                    End of report — CodejaVu Team\n")
	fmt.Fprintf(w, "%s\n", strings.Repeat("═", 72))
	return nil
}

func centerPad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	left := (width - len(s)) / 2
	right := width - len(s) - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}

func protoString(tcp bool) string {
	if tcp {
		return "TCP"
	}
	return "UDP"
}

// effectiveProtoLabel returns a human-readable description of the
// protocol(s) actually used during the run, including auto-TCP promotion.
func effectiveProtoLabel(cfg *Config, qtype uint16) string {
	if cfg.UseTCP {
		return "TCP"
	}
	if shouldAutoTCP(qtype) {
		return fmt.Sprintf("UDP (auto-TCP for %s)", strings.ToUpper(cfg.RecordType))
	}
	return "UDP"
}

// ══════════════════════════════════════════════════════════════════
// Default fallback resolvers
// ══════════════════════════════════════════════════════════════════
var defaultResolvers = []string{
	"1.1.1.1", "1.0.0.1",
	"8.8.8.8", "8.8.4.4",
	"9.9.9.9", "149.112.112.112",
	"208.67.222.222", "208.67.220.220",
}

// ══════════════════════════════════════════════════════════════════
// Main
// ══════════════════════════════════════════════════════════════════
func main() {
	cfg := &Config{}

	// Standard library flag package treats both -x and --x identically and
	// natively accepts single-dash long flags (e.g. -timeout 1000). We register
	// some flags under more than one name so users can use either short or long.
	flag.StringVar(&cfg.ResolverFile, "r", "", "File with resolver IPs")
	flag.StringVar(&cfg.ResolverList, "R", "", "Comma-separated resolver IPs")
	flag.StringVar(&cfg.TargetList, "l", "", "Targets file")
	flag.StringVar(&cfg.RecordType, "t", "A", "DNS record type")
	flag.IntVar(&cfg.Concurrency, "c", 100, "Concurrency")
	flag.IntVar(&cfg.TimeoutMs, "timeout", 3000, "Timeout in ms")
	flag.IntVar(&cfg.ResolversEach, "rc", 5, "Resolvers per target")
	flag.BoolVar(&cfg.UseTCP, "tcp", false, "Use TCP")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose")
	flag.StringVar(&cfg.OutputFile, "o", "", "Output file")
	help := flag.Bool("h", false, "Show help")
	helpLong := flag.Bool("help", false, "Show help")

	flag.Usage = printHelp
	flag.Parse()

	if *help || *helpLong {
		printHelp()
		return
	}

	printBanner()

	// Validate
	if cfg.TargetList == "" {
		fmt.Fprintf(os.Stderr, "%s[!]%s -l (target list) is required. Use -h for help.\n", cBRed, cReset)
		os.Exit(1)
	}
	qtype, err := recordTypeFromString(cfg.RecordType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[!]%s %v\n", cBRed, cReset, err)
		os.Exit(1)
	}
	cfg.qtype = qtype

	// Load targets
	targets, err := loadLines(cfg.TargetList)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[!]%s failed to read target list: %v\n", cBRed, cReset, err)
		os.Exit(1)
	}
	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "%s[!]%s target list is empty\n", cBRed, cReset)
		os.Exit(1)
	}

	// Load resolvers (file → -R list → defaults)
	var resolvers []string
	if cfg.ResolverFile != "" {
		lines, err := loadLines(cfg.ResolverFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[!]%s failed to read resolver file: %v\n", cBRed, cReset, err)
			os.Exit(1)
		}
		for _, l := range lines {
			if n := normalizeResolver(l); n != "" {
				resolvers = append(resolvers, n)
			}
		}
	}
	if cfg.ResolverList != "" {
		for _, r := range strings.Split(cfg.ResolverList, ",") {
			if n := normalizeResolver(r); n != "" {
				resolvers = append(resolvers, n)
			}
		}
	}
	if len(resolvers) == 0 {
		fmt.Fprintf(os.Stderr, "%s[i]%s no resolvers supplied — using built-in defaults\n", cBYellow, cReset)
		for _, r := range defaultResolvers {
			resolvers = append(resolvers, normalizeResolver(r))
		}
	}

	autoTCP := !cfg.UseTCP && shouldAutoTCP(qtype)

	// Color the auto-TCP suffix yellow so the user spots it at a glance.
	protoLabel := protoString(cfg.UseTCP)
	if autoTCP {
		protoLabel = fmt.Sprintf("UDP %s(auto-TCP for %s)%s",
			cBYellow, strings.ToUpper(cfg.RecordType), cBMag)
	}

	// Print run summary
	fmt.Printf("%s┌─ Configuration ────────────────────────────────────┐%s\n", cDim, cReset)
	fmt.Printf("%s│%s %-15s %s%s%s\n", cDim, cReset, "Targets:", cBCyan, fmt.Sprintf("%d", len(targets)), cReset)
	fmt.Printf("%s│%s %-15s %s%s%s\n", cDim, cReset, "Resolvers:", cBCyan, fmt.Sprintf("%d available", len(resolvers)), cReset)
	fmt.Printf("%s│%s %-15s %s%s%s\n", cDim, cReset, "Record type:", cBYellow, strings.ToUpper(cfg.RecordType), cReset)
	fmt.Printf("%s│%s %-15s %s%s%s\n", cDim, cReset, "Protocol:", cBMag, protoLabel, cReset)
	fmt.Printf("%s│%s %-15s %s%d%s\n", cDim, cReset, "Concurrency:", cBGreen, cfg.Concurrency, cReset)
	fmt.Printf("%s│%s %-15s %s%dms%s\n", cDim, cReset, "Timeout:", cBGreen, cfg.TimeoutMs, cReset)
	fmt.Printf("%s│%s %-15s %s%d%s\n", cDim, cReset, "Resolvers/target:", cBGreen, cfg.ResolversEach, cReset)
	if cfg.OutputFile != "" {
		fmt.Printf("%s│%s %-15s %s%s%s\n", cDim, cReset, "Output:", cBBlue, cfg.OutputFile, cReset)
	}
	fmt.Printf("%s└────────────────────────────────────────────────────┘%s\n", cDim, cReset)

	// Warning banner when we auto-promote to TCP, so the user understands
	// why the run might be slower than a plain UDP scan.
	if autoTCP {
		fmt.Printf("\n%s%s ⚠  WARNING %s %s%s record responses are commonly larger than 512 bytes;%s\n",
			cBold+cBYellow, "▌", cReset,
			cYellow, strings.ToUpper(cfg.RecordType), cReset)
		fmt.Printf("%s%s%s %sthis run will use TCP automatically to avoid silent truncation.%s\n",
			cBold+cBYellow, "▌", cReset,
			cYellow, cReset)
		fmt.Printf("%s%s%s %sExpect slightly higher latency than UDP. Pass %s-tcp%s %sto silence this,%s\n",
			cBold+cBYellow, "▌", cReset,
			cYellow, cBCyan, cYellow, cYellow, cReset)
		fmt.Printf("%s%s%s %sor query a different record type to keep UDP.%s\n",
			cBold+cBYellow, "▌", cReset,
			cYellow, cReset)
	}
	fmt.Println()

	atomic.StoreInt64(&totalTargets, int64(len(targets)))
	startTime = time.Now()

	// Set up cancellation on Ctrl-C
	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\n%s[!]%s interrupt received — finishing in-flight queries…\n", cBYellow, cReset)
		cancel()
	}()

	// Progress goroutine
	progDone := make(chan struct{})
	progCtx, progCancel := context.WithCancel(rootCtx)
	go progressTicker(progCtx, progDone)

	// Worker pool
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	jobs := make(chan string, cfg.Concurrency*2)
	resultsCh := make(chan Result, cfg.Concurrency*2)

	var workersWg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		workersWg.Add(1)
		go func() {
			defer workersWg.Done()
			for target := range jobs {
				select {
				case <-rootCtx.Done():
					return
				default:
				}
				res := resolveTarget(rootCtx, target, qtype, strings.ToUpper(cfg.RecordType), resolvers, cfg.ResolversEach, cfg.UseTCP, timeout)
				resultsCh <- res
			}
		}()
	}

	// Result collector
	var collectWg sync.WaitGroup
	var allResults []Result
	var resultsMu sync.Mutex
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for res := range resultsCh {
			atomic.AddInt64(&processedCount, 1)
			if res.Success {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failureCount, 1)
			}
			printResultLive(res, cfg.Verbose)
			resultsMu.Lock()
			allResults = append(allResults, res)
			resultsMu.Unlock()
		}
	}()

	// Feed jobs
	go func() {
		for _, t := range targets {
			select {
			case <-rootCtx.Done():
				break
			case jobs <- t:
			}
		}
		close(jobs)
	}()

	workersWg.Wait()
	close(resultsCh)
	collectWg.Wait()

	progCancel()
	<-progDone

	// Final summary
	elapsed := time.Since(startTime)
	ok := atomic.LoadInt64(&successCount)
	fail := atomic.LoadInt64(&failureCount)
	proc := atomic.LoadInt64(&processedCount)

	fmt.Printf("\n%s┌─ Summary ──────────────────────────────────────────┐%s\n", cBGreen, cReset)
	fmt.Printf("%s│%s %-15s %s%d%s\n", cBGreen, cReset, "Processed:", cBCyan, proc, cReset)
	fmt.Printf("%s│%s %-15s %s%d%s\n", cBGreen, cReset, "Resolved:", cBGreen, ok, cReset)
	fmt.Printf("%s│%s %-15s %s%d%s\n", cBGreen, cReset, "Failed:", cBRed, fail, cReset)
	fmt.Printf("%s│%s %-15s %s%s%s\n", cBGreen, cReset, "Elapsed:", cBYellow, formatDuration(elapsed), cReset)
	if elapsed.Seconds() > 0 {
		fmt.Printf("%s│%s %-15s %s%.1f q/s%s\n", cBGreen, cReset, "Throughput:", cBBlue, float64(proc)/elapsed.Seconds(), cReset)
	}
	fmt.Printf("%s└────────────────────────────────────────────────────┘%s\n", cBGreen, cReset)

	// Save output
	if cfg.OutputFile != "" {
		if err := writeOutput(cfg.OutputFile, allResults, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "%s[!]%s failed to write output: %v\n", cBRed, cReset, err)
			os.Exit(1)
		}
		fmt.Printf("\n%s[✓]%s results written to %s%s%s\n", cBGreen, cReset, cBCyan, cfg.OutputFile, cReset)
	}

	fmt.Printf("\n%s%s%s\n", cDim, "        — CodejaVu Team —", cReset)
}
