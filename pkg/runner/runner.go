package runner

import (
	"context"
	"sync"
	"time"

	"dnshunt/pkg/config"
	"dnshunt/pkg/dns"
	"dnshunt/pkg/reader"
	"dnshunt/pkg/ui"
	"dnshunt/pkg/writer"
)

func Run(ctx context.Context, cfg *config.Config, resolvers []string, stats *dns.Stats, outWriter writer.ResultWriter) {
	jobs := make(chan string, cfg.Concurrency*2)
	resultsCh := make(chan dns.Result, cfg.Concurrency*2)

	var workerWg sync.WaitGroup
	var writerWg sync.WaitGroup

	// Writer Consumer
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		for res := range resultsCh {
			stats.ProcessedCount++
			if res.Success {
				stats.SuccessCount++
			} else {
				stats.FailureCount++
			}
			ui.PrintResultLive(res, cfg.Verbose)
			if outWriter != nil {
				_ = outWriter.Write(res)
			}
		}
	}()

	// Convert milliseconds integer into actual time.Duration
	queryTimeout := time.Duration(cfg.TimeoutMs) * time.Millisecond

	// Worker Pool
	for i := 0; i < cfg.Concurrency; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for target := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				res := dns.ResolveTarget(
					ctx,
					target,
					cfg.QType,
					cfg.RecordType,
					resolvers,
					cfg.ResolversEach,
					cfg.UseTCP,
					queryTimeout,
				)
				resultsCh <- res
			}
		}()
	}

	_ = reader.StreamLines(ctx, cfg.TargetList, jobs)
	close(jobs)

	workerWg.Wait()
	close(resultsCh)
	writerWg.Wait()
}