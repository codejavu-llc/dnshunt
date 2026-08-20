package writer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"dnshunt/pkg/dns"
)

type ResultWriter interface {
	Write(res dns.Result) error
	Close() error
}

type JSONStreamWriter struct {
	file   *os.File
	writer *bufio.Writer
	mu     sync.Mutex
	first  bool
}

func NewJSONStreamWriter(path string) (*JSONStreamWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := bufio.NewWriter(f)
	w.WriteString("[\n")
	return &JSONStreamWriter{file: f, writer: w, first: true}, nil
}

func (j *JSONStreamWriter) Write(res dns.Result) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	data, err := json.MarshalIndent(res, "  ", "  ")
	if err != nil {
		return err
	}

	if !j.first {
		j.writer.WriteString(",\n")
	}
	j.first = false

	j.writer.WriteString("  ")
	j.writer.Write(data)
	return nil
}

func (j *JSONStreamWriter) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.writer.WriteString("\n]\n")
	j.writer.Flush()
	return j.file.Close()
}

type TextStreamWriter struct {
	file   *os.File
	writer *bufio.Writer
	mu     sync.Mutex
}

func NewTextStreamWriter(path string) (*TextStreamWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &TextStreamWriter{file: f, writer: bufio.NewWriter(f)}, nil
}

func (t *TextStreamWriter) Write(res dns.Result) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if res.Success {
		fmt.Fprintf(t.writer, "[+] %s\n", res.Target)
		for _, ans := range res.Answers {
			fmt.Fprintf(t.writer, "      ├─ %s\n", ans)
		}
	} else {
		reason := "no answer"
		if len(res.Errors) > 0 {
			reason = res.Errors[0]
		}
		fmt.Fprintf(t.writer, "[-] %-40s (%s)\n", res.Target, reason)
	}
	return nil
}

func (t *TextStreamWriter) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.writer.Flush()
	return t.file.Close()
}

func NewWriter(path string) (ResultWriter, error) {
	if path == "" {
		return nil, nil
	}
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		return NewJSONStreamWriter(path)
	}
	return NewTextStreamWriter(path)
}