package runner

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/codejavu-llc/dnshunt/pkg/config"
	"github.com/codejavu-llc/dnshunt/pkg/dns"
	"github.com/codejavu-llc/dnshunt/pkg/reader"
	"github.com/codejavu-llc/dnshunt/pkg/writer"
)

type job struct {
	target    string
	qtype     uint16
	qtypeName string
}

type rateLimiter struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func newRateLimiter(rate int) dns.Limiter {
	if rate <= 0 {
		return nil
	}
	return &rateLimiter{interval: time.Second / time.Duration(rate)}
}

func (limiter *rateLimiter) Wait(ctx context.Context) error {
	limiter.mu.Lock()
	now := time.Now()
	if limiter.next.Before(now) {
		limiter.next = now
	}
	wait := time.Until(limiter.next)
	limiter.next = limiter.next.Add(limiter.interval)
	limiter.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Run streams input through the resolver pool and a single serialized writer.
// Resolver fan-out for one job is parallel, so cross-verification adds far less
// wall-clock latency than querying every resolver in series.
func Run(parent context.Context, cfg *config.Config, resolvers []string, stats *dns.Stats, output writer.ResultWriter, input io.Reader) (reader.Report, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	bufferSize := cfg.Concurrency * 2
	if bufferSize > 10000 {
		bufferSize = 10000
	}
	jobs := make(chan job, bufferSize)
	results := make(chan dns.Result, bufferSize)
	limiter := newRateLimiter(cfg.RateLimit)
	options := dns.ResolveOptions{
		ResolversEach: cfg.ResolversEach,
		Consensus:     cfg.Consensus,
		UseTCP:        cfg.UseTCP,
		Timeout:       cfg.Timeout,
		Retries:       cfg.Retries,
		EDNSSize:      uint16(cfg.EDNSSize),
		Limiter:       limiter,
	}

	profiles, err := wildcardProfiles(ctx, cfg, resolvers, options, stats)
	if err != nil {
		return reader.Report{}, err
	}

	var workerWG sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for work := range jobs {
				if ctx.Err() != nil {
					return
				}
				result := dns.ResolveTarget(ctx, work.target, work.qtype, work.qtypeName, resolvers, options)
				if profile := profiles[work.qtype]; profile != nil && profile.Match(result) {
					result.Wildcard = true
					result.WildcardRoot = profile.Domain
					result.Status = "WILDCARD"
					if !cfg.IncludeWildcard {
						result.Success = false
					}
				}
				select {
				case <-ctx.Done():
					return
				case results <- result:
				}
			}
		}()
	}

	var writerWG sync.WaitGroup
	var writeErr error
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		for result := range results {
			stats.ProcessedCount.Add(1)
			stats.QueryCount.Add(int64(dns.ResultQueryCount(result)))
			if result.Wildcard {
				stats.WildcardCount.Add(1)
			}
			if result.Success {
				stats.SuccessCount.Add(1)
			} else {
				stats.FailureCount.Add(1)
			}
			if err := output.Write(result); err != nil && writeErr == nil {
				writeErr = err
				cancel()
			}
		}
	}()

	reportCh := make(chan struct {
		report reader.Report
		err    error
	}, 1)
	go func() {
		targets := make(chan string, bufferSize)
		streamDone := make(chan struct {
			report reader.Report
			err    error
		}, 1)
		go func() {
			report, err := reader.StreamTargets(ctx, input, targets, !cfg.Stream)
			close(targets)
			streamDone <- struct {
				report reader.Report
				err    error
			}{report: report, err: err}
		}()

		for target := range targets {
			for index, qtype := range cfg.QTypes {
				select {
				case <-ctx.Done():
					streamResult := <-streamDone
					close(jobs)
					reportCh <- streamResult
					return
				case jobs <- job{target: target, qtype: qtype, qtypeName: cfg.RecordTypes[index]}:
				}
			}
		}
		streamResult := <-streamDone
		close(jobs)
		reportCh <- streamResult
	}()

	streamResult := <-reportCh
	workerWG.Wait()
	close(results)
	writerWG.Wait()
	if writeErr != nil {
		return streamResult.report, fmt.Errorf("write results: %w", writeErr)
	}
	if streamResult.err != nil && parent.Err() == nil {
		return streamResult.report, fmt.Errorf("read targets: %w", streamResult.err)
	}
	if err := parent.Err(); err != nil {
		return streamResult.report, err
	}
	return streamResult.report, nil
}

func wildcardProfiles(ctx context.Context, cfg *config.Config, resolvers []string, options dns.ResolveOptions, stats *dns.Stats) (map[uint16]*dns.WildcardProfile, error) {
	profiles := make(map[uint16]*dns.WildcardProfile)
	if cfg.WildcardDomain == "" {
		return profiles, nil
	}
	for index, qtype := range cfg.QTypes {
		profile, queries, err := dns.DetectWildcard(ctx, cfg.WildcardDomain, qtype, cfg.RecordTypes[index], resolvers, options, cfg.WildcardTests)
		stats.QueryCount.Add(int64(queries))
		if err != nil {
			return nil, fmt.Errorf("detect wildcard for %s: %w", cfg.RecordTypes[index], err)
		}
		profiles[qtype] = profile
	}
	return profiles, nil
}
