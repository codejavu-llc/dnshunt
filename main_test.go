package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codejavu-llc/dnshunt/pkg/dns"
	mdns "github.com/miekg/dns"
)

func TestRunEndToEndWithStdin(t *testing.T) {
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{PacketConn: connection, Handler: mdns.HandlerFunc(func(writer mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(request)
		response.Answer = []mdns.RR{&mdns.A{
			Hdr: mdns.RR_Header{Name: request.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 120},
			A:   net.ParseIP("192.0.2.80"),
		}}
		_ = writer.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	var stdout, stderr bytes.Buffer
	input := strings.NewReader("Example.COM\nexample.com\ninvalid domain\n")
	exitCode := run(context.Background(), []string{
		"-R", connection.LocalAddr().String(),
		"-rc", "1",
		"-retry", "1",
		"-jsonl",
		"-stats",
	}, input, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("stdout = %q", stdout.String())
	}
	var result dns.Result
	if err := json.Unmarshal([]byte(lines[0]), &result); err != nil {
		t.Fatal(err)
	}
	if result.Target != "example.com" || !result.Success || result.Answers[0] != "192.0.2.80" {
		t.Fatalf("result = %+v", result)
	}
	if !strings.Contains(stderr.String(), "1 invalid") || !strings.Contains(stderr.String(), "1 duplicate") {
		t.Fatalf("summary did not report input hygiene: %q", stderr.String())
	}
}

func TestOutputDestinationsAndFailures(t *testing.T) {
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{PacketConn: connection, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(r)
		switch r.Question[0].Name {
		case "ok.example.":
			response.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: r.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET}, A: net.ParseIP("192.0.2.80")}}
		case "missing.example.":
			response.Rcode = mdns.RcodeNameError
		case "error.example.":
			response.Rcode = mdns.RcodeServerFailure
		}
		_ = w.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	for _, format := range []string{"plain", "text", "json", "jsonl"} {
		for _, file := range []bool{false, true} {
			for _, verbose := range []bool{false, true} {
				for _, failures := range []bool{false, true} {
					args := []string{"-R", connection.LocalAddr().String(), "-retry", "1", "-format", format}
					path := filepath.Join(t.TempDir(), "results")
					if file {
						args = append(args, "-o", path)
					}
					if verbose {
						args = append(args, "-v")
					}
					if failures {
						args = append(args, "-include-failures")
					}
					var stdout, stderr bytes.Buffer
					if code := run(context.Background(), args, strings.NewReader("ok.example\nmissing.example\nempty.example\nerror.example\n"), &stdout, &stderr); code != 0 {
						t.Fatalf("%v: %s", args, stderr.String())
					}
					if file && !verbose && stdout.Len() != 0 {
						t.Fatalf("unexpected CLI results: %q", stdout.String())
					}
					output := stdout.String()
					if file {
						data, err := os.ReadFile(path)
						if err != nil {
							t.Fatal(err)
						}
						output = string(data)
						if verbose && output != stdout.String() {
							t.Fatal("file and stdout differ")
						}
					}
					if !strings.Contains(output, "ok.example") {
						t.Fatalf("missing success: %s", output)
					}
					for _, name := range []string{"missing.example", "empty.example", "error.example"} {
						if strings.Contains(output, name) != failures {
							t.Fatalf("%v: unexpected failure filtering: %s", args, output)
						}
					}
				}
			}
		}
	}
}
