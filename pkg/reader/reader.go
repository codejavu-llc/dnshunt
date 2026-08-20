package reader

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"strings"
)

// StreamLines streams lines from a file sequentially over a channel, keeping RAM overhead near zero.
func StreamLines(ctx context.Context, path string, out chan<- string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := CleanLine(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- line:
		}
	}
	return scanner.Err()
}

// CountLines quickly counts lines in a large file using buffer chunking.
func CountLines(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	buf := make([]byte, 32*1024)
	var count int64
	lineSep := []byte{'\n'}

	for {
		c, err := f.Read(buf)
		count += int64(bytes.Count(buf[:c], lineSep))
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	return count, nil
}

func CleanLine(s string) string {
	s = strings.TrimPrefix(s, "\uFEFF")
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF':
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	return strings.TrimSuffix(s, ".")
}