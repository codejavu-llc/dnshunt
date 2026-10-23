package writer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/codejavu-llc/dnshunt/pkg/dns"
)

func TestJSONLAndFailureFiltering(t *testing.T) {
	var output bytes.Buffer
	stream, err := New(&output, Options{Format: "jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Write(dns.Result{Target: "ok.example", Success: true, Answers: []string{"192.0.2.1"}}); err != nil {
		t.Fatal(err)
	}
	if err := stream.Write(dns.Result{Target: "no.example", Status: "NXDOMAIN"}); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d JSONL lines: %q", len(lines), output.String())
	}
	var result dns.Result
	if err := json.Unmarshal([]byte(lines[0]), &result); err != nil {
		t.Fatal(err)
	}
	if result.Target != "ok.example" {
		t.Fatalf("target = %q", result.Target)
	}
}

func TestJSONArrayAlwaysClosesValidly(t *testing.T) {
	var output bytes.Buffer
	stream, err := New(&output, Options{Format: "json", IncludeFailures: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Write(dns.Result{Target: "example.com", Status: "NODATA"}); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	var results []dns.Result
	if err := json.Unmarshal(output.Bytes(), &results); err != nil {
		t.Fatalf("invalid JSON %q: %v", output.String(), err)
	}
	if len(results) != 1 {
		t.Fatalf("result count = %d", len(results))
	}
}

func TestSilentIncludesFailuresWhenRequested(t *testing.T) {
	var output bytes.Buffer
	stream, err := New(&output, Options{Silent: true, IncludeFailures: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range []dns.Result{{Target: "ok.example", Success: true}, {Target: "missing.example", Status: "NXDOMAIN"}} {
		if err := stream.Write(result); err != nil {
			t.Fatal(err)
		}
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if output.String() != "ok.example\nmissing.example\n" {
		t.Fatalf("output = %q", output.String())
	}
}
