package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/codejavu-llc/dnshunt/pkg/config"
	dnspkg "github.com/codejavu-llc/dnshunt/pkg/dns"
	"github.com/codejavu-llc/dnshunt/pkg/writer"
	mdns "github.com/miekg/dns"
)

func TestRunClassifiesWildcardAndUpdatesStats(t *testing.T) {
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{PacketConn: connection, Handler: mdns.HandlerFunc(func(responseWriter mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(request)
		response.Answer = []mdns.RR{&mdns.A{
			Hdr: mdns.RR_Header{Name: request.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.90"),
		}}
		_ = responseWriter.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	cfg := &config.Config{
		RecordTypes:     []string{"A"},
		QTypes:          []uint16{mdns.TypeA},
		Concurrency:     2,
		Timeout:         time.Second,
		ResolversEach:   1,
		Retries:         1,
		Consensus:       1,
		EDNSSize:        1232,
		WildcardDomain:  "example.com",
		WildcardTests:   2,
		IncludeFailures: true,
	}
	var output bytes.Buffer
	resultWriter, err := writer.New(&output, writer.Options{Format: "jsonl", IncludeFailures: true})
	if err != nil {
		t.Fatal(err)
	}
	stats := dnspkg.NewStats(1)
	report, err := Run(context.Background(), cfg, []string{connection.LocalAddr().String()}, stats, resultWriter, strings.NewReader("candidate.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := resultWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if report.Emitted != 1 {
		t.Fatalf("report = %+v", report)
	}
	processed, success, failed, wildcards, queries, _ := stats.GetCounts()
	if processed != 1 || success != 0 || failed != 1 || wildcards != 1 || queries != 3 {
		t.Fatalf("stats = processed:%d success:%d failed:%d wildcards:%d queries:%d", processed, success, failed, wildcards, queries)
	}
	var result dnspkg.Result
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Wildcard || result.Status != "WILDCARD" || result.Success {
		t.Fatalf("result = %+v", result)
	}
}
