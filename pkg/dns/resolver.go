package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"
)

var supportedTypes = []string{
	"A", "AAAA", "CNAME", "NS", "MX", "TXT", "SRV", "PTR", "SOA", "CAA",
	"HTTPS", "SVCB", "TLSA", "DS", "DNSKEY", "NAPTR", "SSHFP", "CERT", "ANY",
}

type Stats struct {
	TotalTargets   int64
	ProcessedCount atomic.Int64
	SuccessCount   atomic.Int64
	FailureCount   atomic.Int64
	WildcardCount  atomic.Int64
	QueryCount     atomic.Int64
	StartTime      time.Time
}

func NewStats(total int64) *Stats {
	return &Stats{TotalTargets: total, StartTime: time.Now()}
}

func (s *Stats) GetCounts() (processed, success, failed, wildcards, queries, total int64) {
	return s.ProcessedCount.Load(), s.SuccessCount.Load(), s.FailureCount.Load(),
		s.WildcardCount.Load(), s.QueryCount.Load(), s.TotalTargets
}

func (s *Stats) ElapsedSeconds() float64 { return time.Since(s.StartTime).Seconds() }

type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}

type ObservedAnswer struct {
	Answer    string `json:"answer"`
	Resolvers int    `json:"resolvers"`
}

type Result struct {
	Target            string             `json:"target"`
	RecordType        string             `json:"record_type"`
	QueryType         string             `json:"query_type,omitempty"`
	Answers           []string           `json:"answers"`
	Records           []Record           `json:"records,omitempty"`
	ObservedAnswers   []ObservedAnswer   `json:"observed_answers,omitempty"`
	Errors            []string           `json:"errors,omitempty"`
	Resolvers         []ResolverResponse `json:"resolvers"`
	Success           bool               `json:"success"`
	Verified          bool               `json:"verified"`
	ConsensusRequired int                `json:"consensus_required"`
	Status            string             `json:"status"`
	Wildcard          bool               `json:"wildcard,omitempty"`
	WildcardRoot      string             `json:"wildcard_root,omitempty"`
	Timestamp         string             `json:"timestamp"`
}

type ResolverResponse struct {
	Resolver  string   `json:"resolver"`
	Protocol  string   `json:"protocol"`
	RCode     string   `json:"rcode,omitempty"`
	Answers   []string `json:"answers,omitempty"`
	Records   []Record `json:"records,omitempty"`
	Error     string   `json:"error,omitempty"`
	RTTms     int64    `json:"rtt_ms"`
	Attempts  int      `json:"attempts"`
	Queries   int      `json:"queries"`
	Truncated bool     `json:"truncated,omitempty"`
}

type Limiter interface {
	Wait(context.Context) error
}

type ResolveOptions struct {
	ResolversEach int
	Consensus     int
	UseTCP        bool
	Timeout       time.Duration
	Retries       int
	EDNSSize      uint16
	Limiter       Limiter
}

func ParseRecordTypes(raw string) ([]string, []uint16, error) {
	seen := make(map[uint16]bool)
	var names []string
	var values []uint16
	for _, item := range strings.Split(raw, ",") {
		name := strings.ToUpper(strings.TrimSpace(item))
		qtype, err := RecordTypeFromString(name)
		if err != nil {
			return nil, nil, err
		}
		if seen[qtype] {
			continue
		}
		seen[qtype] = true
		names = append(names, name)
		values = append(values, qtype)
	}
	if len(values) == 0 {
		return nil, nil, errors.New("at least one DNS record type is required")
	}
	return names, values, nil
}

func RecordTypeFromString(recordType string) (uint16, error) {
	name := strings.ToUpper(strings.TrimSpace(recordType))
	for _, supported := range supportedTypes {
		if name == supported {
			return mdns.StringToType[name], nil
		}
	}
	return 0, fmt.Errorf("unsupported record type %q (supported: %s)", recordType, strings.Join(supportedTypes, ", "))
}

type endpoint struct {
	protocol   string
	address    string
	serverName string
	url        *url.URL
}

// NormalizeResolver accepts IPv4, IPv6, host:port, and udp://, tcp://,
// tls://, or https:// endpoints and returns a canonical endpoint string.
func NormalizeResolver(raw string) (string, error) {
	ep, err := parseEndpoint(raw, false)
	if err != nil {
		return "", err
	}
	switch ep.protocol {
	case "https":
		return ep.url.String(), nil
	case "udp":
		return ep.address, nil
	default:
		return ep.protocol + "://" + ep.address, nil
	}
}

func parseEndpoint(raw string, forceTCP bool) (endpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return endpoint{}, errors.New("empty resolver")
	}

	protocol := "udp"
	value := raw
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return endpoint{}, fmt.Errorf("invalid resolver %q", raw)
		}
		protocol = strings.ToLower(u.Scheme)
		switch protocol {
		case "http", "https":
			if protocol != "https" {
				return endpoint{}, fmt.Errorf("insecure DoH resolver %q is not supported; use https", raw)
			}
			if u.Path == "" {
				u.Path = "/dns-query"
			}
			return endpoint{protocol: "https", url: u}, nil
		case "udp", "tcp", "tls":
			if u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
				return endpoint{}, fmt.Errorf("resolver %q must not contain credentials, a path, query, or fragment", raw)
			}
			value = u.Host
		default:
			return endpoint{}, fmt.Errorf("unsupported resolver scheme %q", u.Scheme)
		}
	}
	if forceTCP && protocol == "udp" {
		protocol = "tcp"
	}

	defaultPort := "53"
	if protocol == "tls" {
		defaultPort = "853"
	}
	address, host, err := normalizeAddress(value, defaultPort)
	if err != nil {
		return endpoint{}, fmt.Errorf("invalid resolver %q: %w", raw, err)
	}
	return endpoint{protocol: protocol, address: address, serverName: host}, nil
}

func normalizeAddress(value, defaultPort string) (address, host string, err error) {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return net.JoinHostPort(ip.String(), defaultPort), ip.String(), nil
	}
	if parsedHost, port, splitErr := net.SplitHostPort(value); splitErr == nil {
		if parsedHost == "" || port == "" {
			return "", "", errors.New("host and port are required")
		}
		portNumber, portErr := strconv.Atoi(port)
		if portErr != nil || portNumber < 1 || portNumber > 65535 {
			return "", "", errors.New("port must be a number between 1 and 65535")
		}
		parsedHost = strings.Trim(parsedHost, "[]")
		if !validResolverHost(parsedHost) {
			return "", "", errors.New("malformed hostname")
		}
		return net.JoinHostPort(parsedHost, port), parsedHost, nil
	}
	if strings.Contains(value, ":") {
		return "", "", errors.New("malformed IPv6 address; use a raw address or [address]:port")
	}
	if !validResolverHost(value) {
		return "", "", errors.New("malformed hostname")
	}
	return net.JoinHostPort(value, defaultPort), value, nil
}

func validResolverHost(host string) bool {
	if host == "" || strings.ContainsAny(host, " /?#@") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	_, valid := mdns.IsDomainName(host)
	return valid
}

func ResolveTarget(ctx context.Context, target string, qtype uint16, qtypeName string, resolvers []string, opts ResolveOptions) Result {
	result := Result{
		Target:            target,
		RecordType:        strings.ToUpper(qtypeName),
		QueryType:         strings.ToUpper(qtypeName),
		ConsensusRequired: opts.Consensus,
		Timestamp:         time.Now().UTC().Format(time.RFC3339Nano),
	}
	picked := pickResolvers(resolvers, opts.ResolversEach)
	var responses []ResolverResponse
	if opts.Consensus <= 1 {
		// In ordinary resolution, additional resolvers are fallbacks only.
		for _, resolver := range picked {
			if ctx.Err() != nil {
				break
			}
			response := queryResolver(ctx, target, qtype, resolver, opts)
			responses = append(responses, response)
			if response.Error == "" || response.RCode == "NXDOMAIN" {
				break
			}
		}
	} else {
		// Explicit consensus requires independent observations.
		responses = make([]ResolverResponse, len(picked))
		var wg sync.WaitGroup
		for i, resolver := range picked {
			wg.Add(1)
			go func(index int, resolver string) {
				defer wg.Done()
				responses[index] = queryResolver(ctx, target, qtype, resolver, opts)
			}(i, resolver)
		}
		wg.Wait()
	}
	// An address lookup for an alias describes the queried owner as CNAME.
	// Keep the original query type and complete wire records as evidence.
	if qtype == mdns.TypeA || qtype == mdns.TypeAAAA {
		for _, response := range responses {
			for _, record := range response.Records {
				if record.Type == "CNAME" && strings.EqualFold(record.Name, strings.TrimSuffix(target, ".")) {
					result.RecordType = "CNAME"
				}
			}
		}
	}
	for i := range responses {
		responses[i].Answers = nil
		seen := make(map[string]bool)
		for _, record := range responses[i].Records {
			if result.RecordType != "ANY" && record.Type != result.RecordType {
				continue
			}
			if !seen[record.Value] {
				responses[i].Answers = append(responses[i].Answers, record.Value)
				seen[record.Value] = true
			}
		}
		sort.Strings(responses[i].Answers)
	}
	result.Resolvers = responses

	answerCount := make(map[string]int)
	recordCount := make(map[string]int)
	recordByKey := make(map[string]Record)
	rcodes := make(map[string]int)
	for _, response := range responses {
		if response.RCode != "" {
			rcodes[response.RCode]++
		}
		if response.Error != "" {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", response.Resolver, response.Error))
		}
		seenAnswers := make(map[string]bool)
		for _, answer := range response.Answers {
			if !seenAnswers[answer] {
				answerCount[answer]++
				seenAnswers[answer] = true
			}
		}
		seenRecords := make(map[string]bool)
		for _, record := range response.Records {
			if result.RecordType != "ANY" && record.Type != result.RecordType {
				continue
			}
			key := recordKey(record)
			if !seenRecords[key] {
				recordCount[key]++
				recordByKey[key] = record
				seenRecords[key] = true
			}
		}
	}

	for answer, count := range answerCount {
		result.ObservedAnswers = append(result.ObservedAnswers, ObservedAnswer{Answer: answer, Resolvers: count})
		if count >= opts.Consensus {
			result.Answers = append(result.Answers, answer)
		}
	}
	for key, count := range recordCount {
		if count >= opts.Consensus {
			result.Records = append(result.Records, recordByKey[key])
		}
	}
	sort.Strings(result.Answers)
	sort.Slice(result.ObservedAnswers, func(i, j int) bool {
		if result.ObservedAnswers[i].Resolvers == result.ObservedAnswers[j].Resolvers {
			return result.ObservedAnswers[i].Answer < result.ObservedAnswers[j].Answer
		}
		return result.ObservedAnswers[i].Resolvers > result.ObservedAnswers[j].Resolvers
	})
	sort.Slice(result.Records, func(i, j int) bool { return recordKey(result.Records[i]) < recordKey(result.Records[j]) })
	sort.Strings(result.Errors)

	result.Success = len(result.Answers) > 0
	result.Verified = result.Success
	switch {
	case result.Success && rcodes["NXDOMAIN"] > 0 && rcodes["NOERROR"] == 0:
		result.Status = "NXDOMAIN_WITH_ANSWER"
	case result.Success:
		result.Status = "NOERROR"
	case len(answerCount) > 0:
		result.Status = "INCONSISTENT"
	case rcodes["NXDOMAIN"] > 0:
		result.Status = "NXDOMAIN"
	case rcodes["NOERROR"] > 0:
		result.Status = "NODATA"
	default:
		result.Status = "ERROR"
	}
	return result
}

func queryResolver(ctx context.Context, target string, qtype uint16, resolver string, opts ResolveOptions) ResolverResponse {
	response := ResolverResponse{Resolver: resolver}
	ep, err := parseEndpoint(resolver, opts.UseTCP)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Protocol = ep.protocol

	queryName := target
	if qtype == mdns.TypePTR {
		reversed, reverseErr := mdns.ReverseAddr(target)
		if reverseErr != nil {
			response.Error = "PTR target must be an IP address: " + reverseErr.Error()
			return response
		}
		queryName = reversed
	}
	queryName = mdns.Fqdn(queryName)

	message := new(mdns.Msg)
	message.SetQuestion(queryName, qtype)
	message.RecursionDesired = true
	message.SetEdns0(opts.EDNSSize, false)

	started := time.Now()
	defer func() { response.RTTms = time.Since(started).Milliseconds() }()
	for attempt := 1; attempt <= opts.Retries; attempt++ {
		response.Attempts = attempt
		if opts.Limiter != nil {
			if waitErr := opts.Limiter.Wait(ctx); waitErr != nil {
				response.Error = waitErr.Error()
				return response
			}
		}
		response.Queries++
		answer, exchangeErr := exchange(ctx, ep, message, opts.Timeout)
		if exchangeErr != nil {
			response.Error = exchangeErr.Error()
			if ctx.Err() != nil || attempt == opts.Retries {
				return response
			}
			continue
		}

		if answer.Truncated && ep.protocol == "udp" {
			response.Truncated = true
			tcpEndpoint := ep
			tcpEndpoint.protocol = "tcp"
			if opts.Limiter != nil {
				if waitErr := opts.Limiter.Wait(ctx); waitErr != nil {
					response.Error = waitErr.Error()
					return response
				}
			}
			response.Queries++
			answer, exchangeErr = exchange(ctx, tcpEndpoint, message, opts.Timeout)
			if exchangeErr != nil {
				response.Error = "TCP fallback: " + exchangeErr.Error()
				if attempt < opts.Retries {
					continue
				}
				return response
			}
			response.Protocol = "udp+tcp"
		}

		response.RCode = mdns.RcodeToString[answer.Rcode]
		response.Answers, response.Records = extractAnswers(answer.Answer)
		if answer.Rcode == mdns.RcodeSuccess {
			response.Error = ""
			return response
		}
		response.Error = "rcode=" + response.RCode
		if !retryableRCode(answer.Rcode) || attempt == opts.Retries {
			return response
		}
	}
	return response
}

func exchange(ctx context.Context, ep endpoint, message *mdns.Msg, timeout time.Duration) (*mdns.Msg, error) {
	if ep.protocol == "https" {
		wire, err := message.Pack()
		if err != nil {
			return nil, err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.url.String(), bytes.NewReader(wire))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "application/dns-message")
		request.Header.Set("Content-Type", "application/dns-message")
		client := &http.Client{Timeout: timeout}
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			return nil, fmt.Errorf("DoH HTTP status %s", response.Status)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
		if err != nil {
			return nil, err
		}
		answer := new(mdns.Msg)
		if err := answer.Unpack(body); err != nil {
			return nil, err
		}
		return answer, nil
	}

	client := &mdns.Client{Net: ep.protocol, Timeout: timeout}
	if ep.protocol == "udp" {
		if opt := message.IsEdns0(); opt != nil {
			client.UDPSize = opt.UDPSize()
		}
	}
	if ep.protocol == "tls" {
		client.Net = "tcp-tls"
		client.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: ep.serverName}
	}
	answer, _, err := client.ExchangeContext(ctx, message, ep.address)
	return answer, err
}

func retryableRCode(rcode int) bool {
	return rcode == mdns.RcodeServerFailure || rcode == mdns.RcodeRefused
}

func extractAnswers(rrs []mdns.RR) ([]string, []Record) {
	answerSet := make(map[string]bool)
	recordSet := make(map[string]Record)
	for _, rr := range rrs {
		record := recordFromRR(rr)
		if record.Value == "" {
			continue
		}
		answerSet[record.Value] = true
		recordSet[recordKey(record)] = record
	}
	answers := make([]string, 0, len(answerSet))
	for answer := range answerSet {
		answers = append(answers, answer)
	}
	records := make([]Record, 0, len(recordSet))
	for _, record := range recordSet {
		records = append(records, record)
	}
	sort.Strings(answers)
	sort.Slice(records, func(i, j int) bool { return recordKey(records[i]) < recordKey(records[j]) })
	return answers, records
}

func recordFromRR(rr mdns.RR) Record {
	header := rr.Header()
	record := Record{Name: strings.TrimSuffix(header.Name, "."), Type: mdns.TypeToString[header.Rrtype], TTL: header.Ttl}
	switch value := rr.(type) {
	case *mdns.A:
		record.Value = value.A.String()
	case *mdns.AAAA:
		record.Value = value.AAAA.String()
	case *mdns.CNAME:
		record.Value = strings.TrimSuffix(value.Target, ".")
	case *mdns.NS:
		record.Value = strings.TrimSuffix(value.Ns, ".")
	case *mdns.PTR:
		record.Value = strings.TrimSuffix(value.Ptr, ".")
	case *mdns.MX:
		record.Value = fmt.Sprintf("%d %s", value.Preference, strings.TrimSuffix(value.Mx, "."))
	case *mdns.TXT:
		record.Value = strings.Join(value.Txt, "")
	case *mdns.SRV:
		record.Value = fmt.Sprintf("%d %d %d %s", value.Priority, value.Weight, value.Port, strings.TrimSuffix(value.Target, "."))
	case *mdns.SOA:
		record.Value = fmt.Sprintf("%s %s %d %d %d %d %d", strings.TrimSuffix(value.Ns, "."), strings.TrimSuffix(value.Mbox, "."), value.Serial, value.Refresh, value.Retry, value.Expire, value.Minttl)
	case *mdns.CAA:
		record.Value = fmt.Sprintf("%d %s %s", value.Flag, value.Tag, value.Value)
	default:
		fields := strings.Fields(rr.String())
		if len(fields) > 4 {
			record.Value = strings.Join(fields[4:], " ")
		}
	}
	return record
}

func recordKey(record Record) string {
	return record.Name + "\x00" + record.Type + "\x00" + record.Value
}

// pickResolvers samples distinct pool entries in random order without copying the pool.
func pickResolvers(pool []string, count int) []string {
	if count > len(pool) {
		count = len(pool)
	}
	result := make([]string, 0, count)
	swaps := make(map[int]int, count)
	for i := 0; i < count; i++ {
		remaining := len(pool) - i
		index := rand.IntN(remaining)
		selected, ok := swaps[index]
		if !ok {
			selected = index
		}
		last, ok := swaps[remaining-1]
		if !ok {
			last = remaining - 1
		}
		swaps[index] = last
		result = append(result, pool[selected])
	}
	return result
}
