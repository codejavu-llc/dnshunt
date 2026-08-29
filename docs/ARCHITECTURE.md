# Architecture

dnshunt is a streaming Go CLI. It keeps DNS transport, orchestration, presentation, and persistence separate so resolver behavior can be tested without invoking the CLI or using public infrastructure.

```text
file / stdin / arguments
          │
          ▼
  normalize + validate ──► deduplicate (optional)
          │
          ▼
 target × record-type jobs
          │
          ▼
 bounded worker pool ──► parallel resolver fan-out
          │                    │
          │                    ├─ rate limit
          │                    ├─ retry transient failures
          │                    ├─ UDP → TCP on truncation
          │                    └─ UDP / TCP / DoT / DoH
          │
          ▼
 consensus aggregation ──► wildcard classification
          │
          ▼
 single serialized consumer
          ├─ atomic statistics
          ├─ stdout formatter
          └─ optional file formatter
```

## Packages

- `pkg/config`: isolated flag parsing and validation; never exits the process.
- `pkg/reader`: streaming input hygiene, IDN conversion, DNS-name validation, and optional deduplication.
- `pkg/dns`: resolver endpoint parsing, DNS exchanges, retries, transport fallback, record normalization, consensus aggregation, wildcard profiling, and statistics.
- `pkg/runner`: bounded work scheduling, global query rate limiting, cancellation, wildcard application, and serialized result delivery.
- `pkg/writer`: plain, detailed text, JSONL, and JSON output with write-error propagation.
- `pkg/ui`: terminal-only banner, progress, color, and summary rendering.

## Concurrency model

`-c` bounds target/type jobs. A job queries up to `-rc` resolvers concurrently, making the approximate maximum in-flight exchanges `c × rc`. A single result consumer owns output ordering and write state. The global rate limiter is shared by all resolver goroutines and counts retries and TCP fallbacks as separate wire queries.

Resolver selection is deterministic for a target/type pair. It rotates the starting point through the resolver pool, producing repeatable evidence without sending every target to the same subset.

## Consensus model

Every resolver response is preserved. Answers are canonicalized independently from TTL, then counted at most once per resolver. An answer is accepted when its count meets `-consensus`; one resolver cannot inflate agreement by returning duplicates. Records use name, type, and value as their identity, while a representative TTL is preserved for reporting.

Answers that fail consensus remain in `observed_answers`, allowing users to audit poisoned, geo-dependent, load-balanced, or stale data. NXDOMAIN answers are parsed before response-code classification so dangling CNAME evidence is not discarded.

## Cancellation and errors

SIGINT and SIGTERM cancel the root context. Producers, workers, rate-limit waits, and network exchanges observe that context. Writer failures cancel the pipeline and are returned to the caller. JSON arrays are closed during orderly shutdown; JSONL is recommended when abrupt process termination must leave every completed record independently parseable.

## Memory behavior

Input and output are streamed. Default deduplication stores normalized target names, and file mode performs an initial validation pass to render exact progress. `-stream` disables both features, keeping memory independent of input size and supporting unbounded stdin.

## Trust boundary

DNS answers are untrusted network data. dnshunt limits DoH response reads to DNS message size, validates input and resolver endpoints, verifies DoT/DoH TLS certificates, avoids shell execution, and encodes structured output with the standard JSON library. Consensus improves confidence but does not make correlated resolvers independent; users should select providers and network paths appropriate to their threat model.
