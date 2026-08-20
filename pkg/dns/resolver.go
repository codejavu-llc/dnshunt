package dns

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type Stats struct {
	TotalTargets   int64
	ProcessedCount int64
	SuccessCount   int64
	FailureCount   int64
	StartTime      time.Time
	Ticker         *time.Ticker
}

func NewStats(total int64) *Stats {
	return &Stats{
		TotalTargets: total,
		StartTime:    time.Now(),
		Ticker:       time.NewTicker(150 * time.Millisecond),
	}
}

func (s *Stats) GetCounts() (proc, ok, fail, total int64) {
	return atomic.LoadInt64(&s.ProcessedCount),
		atomic.LoadInt64(&s.SuccessCount),
		atomic.LoadInt64(&s.FailureCount),
		s.TotalTargets
}

func (s *Stats) ElapsedSeconds() float64 {
	return time.Since(s.StartTime).Seconds()
}

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

func RecordTypeFromString(t string) (uint16, error) {
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

func ShouldAutoTCP(qtype uint16) bool {
	switch qtype {
	case dns.TypeTXT, dns.TypeMX, dns.TypeCAA, dns.TypeSOA:
		return true
	}
	return false
}

func NormalizeResolver(r string) string {
	r = strings.TrimSpace(r)
	if r == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(r); err == nil {
		return r
	}
	return r + ":53"
}

func ResolveTarget(ctx context.Context, target string, qtype uint16, qtypeStr string, resolvers []string, n int, useTCP bool, timeout time.Duration) Result {
	res := Result{
		Target:     target,
		RecordType: qtypeStr,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

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
	if !res.Success && noerrorEmpty > 0 && len(res.Errors) == 0 {
		res.Errors = append(res.Errors, fmt.Sprintf("NOERROR/empty from %d resolver(s)", noerrorEmpty))
	}
	return res
}

func queryResolver(ctx context.Context, target string, qtype uint16, resolver string, useTCP bool, timeout time.Duration) ResolverResponse {
	resp := ResolverResponse{Resolver: resolver}
	effectiveTCP := useTCP || ShouldAutoTCP(qtype)

	c := &dns.Client{Timeout: timeout}
	if effectiveTCP {
		c.Net = "tcp"
	} else {
		c.Net = "udp"
		c.UDPSize = 4096
	}

	queryName := target
	if qtype == dns.TypePTR {
		if r, err := dns.ReverseAddr(target); err == nil {
			queryName = r
		}
	}
	if !strings.HasSuffix(queryName, ".") {
		queryName += "."
	}

	m := new(dns.Msg)
	m.SetQuestion(queryName, qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, false)

	start := time.Now()
	in, _, err := c.ExchangeContext(ctx, m, resolver)
	resp.RTTms = time.Since(start).Milliseconds()

	if err != nil {
		resp.Error = err.Error()
		return resp
	}

	if in != nil && in.Truncated && !effectiveTCP {
		tcpClient := &dns.Client{Net: "tcp", Timeout: timeout}
		tcpStart := time.Now()
		in2, _, err2 := tcpClient.ExchangeContext(ctx, m, resolver)
		resp.RTTms += time.Since(tcpStart).Milliseconds()
		if err2 == nil && in2 != nil {
			in = in2
		}
	}

	if in.Rcode != dns.RcodeSuccess {
		resp.Error = fmt.Sprintf("rcode=%s", dns.RcodeToString[in.Rcode])
		return resp
	}

	for _, rr := range in.Answer {
		resp.Answers = append(resp.Answers, formatAnswer(rr))
	}
	return resp
}

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
	default:
		return rr.String()
	}
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