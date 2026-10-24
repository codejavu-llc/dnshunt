package dns

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func startDNSServer(t *testing.T, handler mdns.Handler) string {
	t.Helper()
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := tcpListener.Addr().(*net.TCPAddr).Port
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		_ = tcpListener.Close()
		t.Fatal(err)
	}
	udpServer := &mdns.Server{PacketConn: udpConn, Handler: handler}
	tcpServer := &mdns.Server{Listener: tcpListener, Handler: handler}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func aHandler(ip string) mdns.Handler {
	return mdns.HandlerFunc(func(writer mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(request)
		response.Answer = []mdns.RR{&mdns.A{
			Hdr: mdns.RR_Header{Name: request.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
			A:   net.ParseIP(ip),
		}}
		_ = writer.WriteMsg(response)
	})
}

func testOptions(resolvers, consensus, retries int) ResolveOptions {
	return ResolveOptions{
		ResolversEach: resolvers,
		Consensus:     consensus,
		Timeout:       time.Second,
		Retries:       retries,
		EDNSSize:      1232,
	}
}

func TestResolveTargetStopsAfterNoError(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(strconv.FormatBool(empty), func(t *testing.T) {
			var queries atomic.Int32
			handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
				queries.Add(1)
				if empty {
					response := new(mdns.Msg)
					response.SetReply(r)
					_ = w.WriteMsg(response)
					return
				}
				aHandler("192.0.2.20").ServeDNS(w, r)
			})
			one := startDNSServer(t, handler)
			two := startDNSServer(t, handler)
			result := ResolveTarget(context.Background(), "stop.example", mdns.TypeA, "A", []string{one, two}, testOptions(2, 1, 2))
			if queries.Load() != 1 || len(result.Resolvers) != 1 || result.Resolvers[0].Error != "" {
				t.Fatalf("expected one successful exchange, queries=%d result=%+v", queries.Load(), result)
			}
		})
	}
}

func TestResolveTargetStopsAfterNXDomain(t *testing.T) {
	var queries atomic.Int32
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		queries.Add(1)
		response := new(mdns.Msg)
		response.SetRcode(r, mdns.RcodeNameError)
		_ = w.WriteMsg(response)
	})
	one := startDNSServer(t, handler)
	two := startDNSServer(t, handler)
	result := ResolveTarget(context.Background(), "missing.example", mdns.TypeA, "A", []string{one, two}, testOptions(2, 1, 2))
	if queries.Load() != 1 || len(result.Resolvers) != 1 || result.Status != "NXDOMAIN" {
		t.Fatalf("expected terminal NXDOMAIN, queries=%d result=%+v", queries.Load(), result)
	}
}

func TestResolveTargetFallsBackAfterError(t *testing.T) {
	// All endpoints share a counter so the first selected resolver fails,
	// regardless of the random selection order.
	for _, rcode := range []int{mdns.RcodeServerFailure, mdns.RcodeRefused, -1} {
		t.Run(strconv.Itoa(rcode), func(t *testing.T) {
			var queries atomic.Int32
			handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
				if queries.Add(1) <= 2 {
					if rcode == -1 {
						return // Simulate a timeout.
					}
					response := new(mdns.Msg)
					response.SetRcode(r, rcode)
					_ = w.WriteMsg(response)
					return
				}
				aHandler("192.0.2.20").ServeDNS(w, r)
			})
			one := startDNSServer(t, handler)
			two := startDNSServer(t, handler)
			three := startDNSServer(t, handler)
			opts := testOptions(3, 1, 2)
			opts.Timeout = 50 * time.Millisecond
			result := ResolveTarget(context.Background(), "fallback.example", mdns.TypeA, "A", []string{one, two, three}, opts)
			if !result.Success || len(result.Resolvers) != 2 || queries.Load() != 3 {
				t.Fatalf("unexpected fallback: queries=%d result=%+v", queries.Load(), result)
			}
			if result.Resolvers[0].Resolver == result.Resolvers[1].Resolver {
				t.Fatal("fallback reused the failed resolver")
			}
		})
	}
}

func TestPickResolversWithoutReplacement(t *testing.T) {
	pool := []string{"one", "two", "three", "four"}
	for _, count := range []int{1, 3, 4, 5} {
		picked := pickResolvers(pool, count)
		if len(picked) != min(count, len(pool)) {
			t.Fatalf("incorrect sample size: %v", picked)
		}
		seen := make(map[string]bool)
		for _, resolver := range picked {
			if seen[resolver] {
				t.Fatalf("duplicate resolver: %v", picked)
			}
			seen[resolver] = true
		}
	}
}

func TestResolveTargetUsesConsensus(t *testing.T) {
	one := startDNSServer(t, aHandler("192.0.2.10"))
	two := startDNSServer(t, aHandler("192.0.2.10"))
	three := startDNSServer(t, aHandler("192.0.2.99"))

	result := ResolveTarget(context.Background(), "consensus.example", mdns.TypeA, "A", []string{one, two, three}, testOptions(3, 2, 1))
	if !result.Success || !result.Verified {
		t.Fatalf("expected verified success: %+v", result)
	}
	if len(result.Answers) != 1 || result.Answers[0] != "192.0.2.10" {
		t.Fatalf("answers = %v", result.Answers)
	}
	if len(result.ObservedAnswers) != 2 || result.ObservedAnswers[0].Resolvers != 2 {
		t.Fatalf("observations = %+v", result.ObservedAnswers)
	}
}

func TestResolveTargetFansOutResolversConcurrently(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	handler := mdns.HandlerFunc(func(writer mdns.ResponseWriter, request *mdns.Msg) {
		started <- struct{}{}
		<-release
		aHandler("192.0.2.20").ServeDNS(writer, request)
	})
	one := startDNSServer(t, handler)
	two := startDNSServer(t, handler)
	resultCh := make(chan Result, 1)
	go func() {
		resultCh <- ResolveTarget(context.Background(), "parallel.example", mdns.TypeA, "A", []string{one, two}, testOptions(2, 2, 1))
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("resolvers were not queried concurrently")
		}
	}
	close(release)
	if result := <-resultCh; !result.Success {
		t.Fatalf("resolution failed: %+v", result)
	}
}

func TestUDPTruncationFallsBackToTCP(t *testing.T) {
	handler := mdns.HandlerFunc(func(writer mdns.ResponseWriter, request *mdns.Msg) {
		if strings.HasPrefix(writer.LocalAddr().Network(), "udp") {
			response := new(mdns.Msg)
			response.SetReply(request)
			response.Truncated = true
			_ = writer.WriteMsg(response)
			return
		}
		aHandler("192.0.2.30").ServeDNS(writer, request)
	})
	server := startDNSServer(t, handler)
	result := ResolveTarget(context.Background(), "large.example", mdns.TypeA, "A", []string{server}, testOptions(1, 1, 1))
	if !result.Success || result.Resolvers[0].Protocol != "udp+tcp" || result.Resolvers[0].Queries != 2 {
		t.Fatalf("unexpected fallback result: %+v", result)
	}
}

func TestRetryAndNXDomainCNAMEEvidence(t *testing.T) {
	var attempts atomic.Int32
	retryServer := startDNSServer(t, mdns.HandlerFunc(func(writer mdns.ResponseWriter, request *mdns.Msg) {
		if attempts.Add(1) == 1 {
			response := new(mdns.Msg)
			response.SetRcode(request, mdns.RcodeServerFailure)
			_ = writer.WriteMsg(response)
			return
		}
		aHandler("192.0.2.40").ServeDNS(writer, request)
	}))
	result := ResolveTarget(context.Background(), "retry.example", mdns.TypeA, "A", []string{retryServer}, testOptions(1, 1, 2))
	if !result.Success || result.Resolvers[0].Attempts != 2 {
		t.Fatalf("retry did not recover: %+v", result)
	}

	nxServer := startDNSServer(t, mdns.HandlerFunc(func(writer mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetRcode(request, mdns.RcodeNameError)
		response.Answer = []mdns.RR{&mdns.CNAME{
			Hdr:    mdns.RR_Header{Name: request.Question[0].Name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 60},
			Target: "unclaimed.vendor.example.",
		}}
		_ = writer.WriteMsg(response)
	}))
	nxResult := ResolveTarget(context.Background(), "dangling.example", mdns.TypeA, "A", []string{nxServer}, testOptions(1, 1, 1))
	if !nxResult.Success || nxResult.Status != "NXDOMAIN_WITH_ANSWER" || nxResult.Answers[0] != "unclaimed.vendor.example" {
		t.Fatalf("lost NXDOMAIN CNAME evidence: %+v", nxResult)
	}
}

func TestNormalizeResolverTransportsAndIPv6(t *testing.T) {
	tests := map[string]string{
		"1.1.1.1":                               "1.1.1.1:53",
		"[2001:db8::1]:5353":                    "[2001:db8::1]:5353",
		"2001:db8::1":                           "[2001:db8::1]:53",
		"tcp://resolver.example":                "tcp://resolver.example:53",
		"tls://resolver.example":                "tls://resolver.example:853",
		"https://resolver.example":              "https://resolver.example/dns-query",
		"https://resolver.example/custom-query": "https://resolver.example/custom-query",
	}
	for input, want := range tests {
		got, err := NormalizeResolver(input)
		if err != nil {
			t.Errorf("NormalizeResolver(%q): %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeResolver(%q) = %q, want %q", input, got, want)
		}
	}
	if _, err := NormalizeResolver("http://resolver.example/dns-query"); err == nil {
		t.Fatal("insecure DoH endpoint was accepted")
	}
}

func TestWildcardProfileMatchesOnlyKnownAnswerPool(t *testing.T) {
	server := startDNSServer(t, aHandler("192.0.2.55"))
	options := testOptions(1, 1, 1)
	profile, queries, err := DetectWildcard(context.Background(), "example.com", mdns.TypeA, "A", []string{server}, options, 3)
	if err != nil {
		t.Fatal(err)
	}
	if profile == nil || queries != 3 {
		t.Fatalf("profile = %+v, queries = %d", profile, queries)
	}
	wildcard := ResolveTarget(context.Background(), "random.example.com", mdns.TypeA, "A", []string{server}, options)
	if !profile.Match(wildcard) {
		t.Fatal("expected wildcard response to match profile")
	}
	legitimate := wildcard
	legitimate.Answers = []string{"192.0.2.99"}
	if profile.Match(legitimate) {
		t.Fatal("unseen legitimate answer matched wildcard profile")
	}
	outside := wildcard
	outside.Target = "outside.test"
	if profile.Match(outside) {
		t.Fatal("out-of-scope target matched wildcard profile")
	}
}

func TestAliasConsensusAndWildcard(t *testing.T) {
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(r)
		response.Answer = []mdns.RR{
			&mdns.CNAME{Hdr: mdns.RR_Header{Name: r.Question[0].Name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET}, Target: "edge.example."},
			&mdns.A{Hdr: mdns.RR_Header{Name: "edge.example.", Rrtype: mdns.TypeA, Class: mdns.ClassINET}, A: net.ParseIP("192.0.2.10")},
		}
		_ = w.WriteMsg(response)
	})
	one := startDNSServer(t, handler)
	two := startDNSServer(t, handler)
	opts := testOptions(2, 2, 1)
	result := ResolveTarget(context.Background(), "alias.example", mdns.TypeA, "A", []string{one, two}, opts)
	if !result.Success || result.RecordType != "CNAME" || len(result.Answers) != 1 || result.Answers[0] != "edge.example" {
		t.Fatalf("unexpected consensus: %+v", result)
	}
	profile, _, err := DetectWildcard(context.Background(), "example", mdns.TypeA, "A", []string{one, two}, opts, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !profile.Match(result) {
		t.Fatal("alias wildcard no longer matches address queries")
	}
}
