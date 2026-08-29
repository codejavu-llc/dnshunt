package reader

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

type Report struct {
	Read       int64
	Emitted    int64
	Duplicates int64
	Invalid    int64
}

// StreamTargets validates and streams targets. Dedupe mode is ideal for recon
// lists; disabling it keeps memory usage constant for extremely large inputs.
func StreamTargets(ctx context.Context, input io.Reader, out chan<- string, dedupe bool) (Report, error) {
	var report Report
	var seen map[string]struct{}
	if dedupe {
		seen = make(map[string]struct{})
	}
	scanner := newScanner(input)
	for scanner.Scan() {
		report.Read++
		raw := CleanLine(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		target, err := NormalizeTarget(raw)
		if err != nil {
			report.Invalid++
			continue
		}
		if dedupe {
			if _, exists := seen[target]; exists {
				report.Duplicates++
				continue
			}
			seen[target] = struct{}{}
		}
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		case out <- target:
			report.Emitted++
		}
	}
	return report, scanner.Err()
}

func StreamFile(ctx context.Context, path string, out chan<- string, dedupe bool) (Report, error) {
	file, err := os.Open(path)
	if err != nil {
		return Report{}, err
	}
	defer file.Close()
	return StreamTargets(ctx, file, out, dedupe)
}

func CountTargets(input io.Reader, dedupe bool) (Report, error) {
	out := make(chan string, 256)
	result := make(chan struct {
		report Report
		err    error
	}, 1)
	go func() {
		report, err := StreamTargets(context.Background(), input, out, dedupe)
		close(out)
		result <- struct {
			report Report
			err    error
		}{report: report, err: err}
	}()
	for range out {
	}
	value := <-result
	return value.report, value.err
}

func CountFile(path string, dedupe bool) (Report, error) {
	file, err := os.Open(path)
	if err != nil {
		return Report{}, err
	}
	defer file.Close()
	return CountTargets(file, dedupe)
}

// ReadRawLines is used for resolver files, where URL schemes and ports must be
// preserved instead of applying hostname normalization.
func ReadRawLines(input io.Reader) ([]string, error) {
	var lines []string
	scanner := newScanner(input)
	for scanner.Scan() {
		line := CleanLine(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}

func ReadRawFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ReadRawLines(file)
}

func NormalizeTarget(raw string) (string, error) {
	target := CleanLine(raw)
	if target == "" {
		return "", fmt.Errorf("empty target")
	}
	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Hostname() == "" {
			return "", fmt.Errorf("invalid URL target %q", raw)
		}
		target = parsed.Hostname()
	} else if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}
	target = strings.TrimPrefix(target, "*.")
	target = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	if ip := net.ParseIP(strings.Trim(target, "[]")); ip != nil {
		return ip.String(), nil
	}
	// Service-discovery owners such as _sip._tcp.example.com intentionally use
	// underscores and are DNS names, but are not IDNA hostnames.
	if strings.Contains(target, "_") {
		for _, char := range target {
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' {
				continue
			}
			return "", fmt.Errorf("invalid DNS service name %q", raw)
		}
		if _, valid := dns.IsDomainName(target); !valid || strings.Contains(target, "..") {
			return "", fmt.Errorf("invalid DNS service name %q", raw)
		}
		return target, nil
	}

	ascii, err := idna.Lookup.ToASCII(target)
	if err != nil {
		return "", fmt.Errorf("invalid internationalized domain %q: %w", raw, err)
	}
	if _, valid := dns.IsDomainName(ascii); !valid || strings.Contains(ascii, "..") {
		return "", fmt.Errorf("invalid DNS name %q", raw)
	}
	return strings.ToLower(ascii), nil
}

func CleanLine(value string) string {
	value = strings.TrimPrefix(value, "\uFEFF")
	value = strings.Map(func(char rune) rune {
		switch char {
		case '\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF':
			return -1
		default:
			return char
		}
	}, value)
	return strings.TrimSpace(value)
}

func newScanner(input io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	return scanner
}
