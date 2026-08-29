package writer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/codejavu-llc/dnshunt/pkg/dns"
)

type ResultWriter interface {
	Write(dns.Result) error
	Close() error
}

type Options struct {
	Format          string
	Silent          bool
	Verbose         bool
	IncludeFailures bool
}

type streamWriter struct {
	mu      sync.Mutex
	buffer  *bufio.Writer
	closer  io.Closer
	options Options
	first   bool
	closed  bool
}

func New(output io.Writer, options Options) (ResultWriter, error) {
	if output == nil {
		return nil, fmt.Errorf("output writer is nil")
	}
	if options.Format == "" {
		options.Format = "plain"
	}
	switch options.Format {
	case "plain", "text", "jsonl", "json":
	default:
		return nil, fmt.Errorf("unsupported output format %q", options.Format)
	}
	result := &streamWriter{buffer: bufio.NewWriter(output), options: options, first: true}
	if options.Format == "json" {
		if _, err := result.buffer.WriteString("[\n"); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func NewFile(path string, options Options) (ResultWriter, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	result, err := New(file, options)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	result.(*streamWriter).closer = file
	return result, nil
}

func (stream *streamWriter) Write(result dns.Result) error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed {
		return fmt.Errorf("write after close")
	}
	if !result.Success && !stream.options.IncludeFailures {
		return nil
	}

	switch stream.options.Format {
	case "plain":
		return stream.writePlain(result)
	case "text":
		return stream.writeText(result)
	case "jsonl":
		data, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if _, err := stream.buffer.Write(data); err != nil {
			return err
		}
		return stream.buffer.WriteByte('\n')
	case "json":
		data, err := json.MarshalIndent(result, "  ", "  ")
		if err != nil {
			return err
		}
		if !stream.first {
			if _, err := stream.buffer.WriteString(",\n"); err != nil {
				return err
			}
		}
		stream.first = false
		if _, err := stream.buffer.WriteString("  "); err != nil {
			return err
		}
		_, err = stream.buffer.Write(data)
		return err
	default:
		return fmt.Errorf("unsupported output format %q", stream.options.Format)
	}
}

func (stream *streamWriter) writePlain(result dns.Result) error {
	if stream.options.Silent {
		if !result.Success {
			return nil
		}
		_, err := fmt.Fprintln(stream.buffer, result.Target)
		return err
	}
	if result.Success {
		_, err := fmt.Fprintf(stream.buffer, "%s [%s] %s\n", result.Target, result.RecordType, strings.Join(result.Answers, ", "))
		return err
	}
	_, err := fmt.Fprintf(stream.buffer, "%s [%s] - %s\n", result.Target, result.RecordType, result.Status)
	return err
}

func (stream *streamWriter) writeText(result dns.Result) error {
	marker := "+"
	if !result.Success {
		marker = "-"
	}
	if _, err := fmt.Fprintf(stream.buffer, "[%s] %s %s (%s)\n", marker, result.Target, result.RecordType, result.Status); err != nil {
		return err
	}
	for _, record := range result.Records {
		if _, err := fmt.Fprintf(stream.buffer, "    %-7s %-6d %s\n", record.Type, record.TTL, record.Value); err != nil {
			return err
		}
	}
	if stream.options.Verbose {
		for _, response := range result.Resolvers {
			status := response.RCode
			if response.Error != "" {
				status = response.Error
			}
			if _, err := fmt.Fprintf(stream.buffer, "    @%-24s %-7s %4dms %s\n", response.Resolver, response.Protocol, response.RTTms, status); err != nil {
				return err
			}
		}
	}
	return nil
}

func (stream *streamWriter) Close() error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closed {
		return nil
	}
	stream.closed = true
	if stream.options.Format == "json" {
		if _, err := stream.buffer.WriteString("\n]\n"); err != nil {
			return err
		}
	}
	if err := stream.buffer.Flush(); err != nil {
		return err
	}
	if stream.closer != nil {
		return stream.closer.Close()
	}
	return nil
}

type multiWriter struct{ writers []ResultWriter }

func Multi(writers ...ResultWriter) ResultWriter {
	filtered := make([]ResultWriter, 0, len(writers))
	for _, item := range writers {
		if item != nil {
			filtered = append(filtered, item)
		}
	}
	return &multiWriter{writers: filtered}
}

func (multi *multiWriter) Write(result dns.Result) error {
	for _, item := range multi.writers {
		if err := item.Write(result); err != nil {
			return err
		}
	}
	return nil
}

func (multi *multiWriter) Close() error {
	var firstError error
	for _, item := range multi.writers {
		if err := item.Close(); err != nil && firstError == nil {
			firstError = err
		}
	}
	return firstError
}
