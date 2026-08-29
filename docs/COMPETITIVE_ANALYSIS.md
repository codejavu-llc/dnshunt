# Competitive analysis and product strategy

Research date: 2026-08-29. Sources are upstream project documentation and repositories rather than third-party listicles.

## Executive conclusion

dnshunt should not compete with MassDNS on raw packet throughput or with full asset-discovery platforms on feature count. Its defensible category is **fast, explainable DNS validation with cross-resolver evidence**. Bug-bounty workflows frequently trade between speed and clean results; dnshunt can own the decision point by showing exactly which resolver endpoints observed an answer and enforcing an explicit consensus policy.

Before this upgrade, that promise was only partially implemented: resolvers were queried serially, answers were merged without measuring agreement, retries and rate limits were absent, input required a file, JSON used an interruption-sensitive array only, wildcard responses were not detected, resolver errors were swallowed, IPv6 resolver normalization was incorrect, and the repository could not build cleanly because it had no module metadata.

The current implementation closes those foundational gaps. It does not claim to replace all mature tools; the remaining differentiators needed for category leadership are listed in the roadmap.

## Comparable tools

### dnsx

[ProjectDiscovery dnsx](https://github.com/projectdiscovery/dnsx) is the closest general-purpose Go CLI. Its strengths are broad pipeline ergonomics, brute force, automatic wildcard handling, retry/rate controls, UDP/TCP/DoT/DoH resolver formats, response-code filtering, JSONL, CDN/ASN enrichment, tracing, resume, and library use. It is the feature-completeness benchmark.

Opportunity for dnshunt: dnsx normally focuses on fast resolution through retryable resolvers. dnshunt can make multi-resolver observations and the consensus decision first-class output instead of treating resolver rotation as an implementation detail.

### puredns

[puredns](https://github.com/d3mondev/puredns) is the clean-results benchmark for bug bounty. Its documented three-stage flow is mass resolution, wildcard detection, and slower validation through trusted resolvers. It supports stdin, quiet pipeline output, bruteforce, rate limits, wildcard test tuning, and separate output for valid names and wildcard roots. It depends on MassDNS.

Opportunity for dnshunt: provide comparable cleanliness without an external binary, then exceed its auditability with per-resolver evidence, encrypted transports, multi-record scans, consensus, and explicit inconsistent-result output. puredns documentation also notes that it does not deduplicate input; dnshunt does so by default.

### shuffleDNS

[ProjectDiscovery shuffleDNS](https://github.com/projectdiscovery/shuffledns) wraps MassDNS for resolution and active bruteforce. Its standout behavior is adaptive, multi-level wildcard handling based on repeated IPs, with trusted-resolver validation and simple stdin/stdout integration. It also requires a MassDNS installation and resolver list.

Opportunity for dnshunt: retain single-binary operation and richer DNS evidence. Its wildcard implementation must eventually become automatic and multi-level to reach parity with shuffleDNS on diverse target lists.

### MassDNS

[MassDNS](https://github.com/blechschmidt/massdns) is the raw-throughput benchmark. Its upstream README reports more than 350,000 names per second in suitable conditions, offers text/binary/NDJSON output, response-code filters, retries, source binding, and exposes the answering resolver. It is a specialized, single-threaded, event-driven stub resolver rather than a verification workflow.

Opportunity for dnshunt: do not make unsupported speed claims. Optimize for reliable Go-level throughput at normal bug-bounty scale, controlled load, encrypted transports, and explainable validation. MassDNS's own roadmap calls out cross-resolver checks, wildcard detection, and trusted revalidation—the exact layer dnshunt is positioned to provide.

### ZDNS

[ZMap ZDNS](https://github.com/zmap/zdns) is the large-scale measurement and protocol-depth benchmark. It provides iterative resolution, a recursive resolver/cache, many raw record modules, lookup modules that perform follow-up address resolution, multiple modules per run, field-selectable JSON detail, nameserver mode, and very high goroutine parallelism.

Opportunity for dnshunt: stay easier to operate for reconnaissance pipelines while borrowing its rigor: stable schemas, benchmarks, library boundaries, iterative/authoritative querying, and selective verbosity.

### DNS Validator and hakrevdns

[DNS Validator](https://github.com/vortexau/dnsvalidator) specializes in curating public resolvers by comparing stable baseline answers and checking expected NXDOMAIN behavior. [hakrevdns](https://github.com/hakluke/hakrevdns) demonstrates the value of a tiny, pipe-friendly reverse-DNS tool with configurable resolvers.

Opportunity for dnshunt: resolver health scoring and quarantine should become part of long runs, while PTR output must stay as easy to pipe as a dedicated reverse lookup utility.

## Feature matrix after this upgrade

| Capability | dnshunt | dnsx | puredns | shuffleDNS | MassDNS | ZDNS |
|---|---:|---:|---:|---:|---:|---:|
| Single Go binary | Yes | Yes | No (MassDNS) | No (MassDNS) | Native C binary | Yes |
| stdin/stdout pipeline | Yes | Yes | Yes | Yes | Yes | Yes |
| Multi-record run | Yes | Yes | No | No | One type/run | Yes |
| UDP/TCP/DoT/DoH | Yes | Yes | Via MassDNS/trusted resolver path | Via dependencies | UDP/TCP | Broad modes |
| Retries and global rate limit | Yes | Yes | Yes | Retries/concurrency | Retries/concurrency | Concurrency controls |
| Automatic UDP truncation fallback | Yes | Library-dependent | MassDNS-dependent | MassDNS-dependent | Config-dependent | Yes |
| Wildcard filtering | Scoped/manual | Automatic/manual | Automatic | Automatic multi-level | No | No |
| Separate trusted validation phase | Not yet | Resolver selection | Yes | Yes | No | No |
| Explicit answer consensus threshold | **Yes** | Not a primary output concept | Validation decision | Validation decision | No | No |
| Per-resolver evidence and agreement count | **Yes** | Raw JSON detail | Intermediate files | Limited | Resolver in output | Resolver/detail fields |
| Input normalize, validate, deduplicate | Yes | Yes | Sanitizes, no dedupe | Unique valid output | Limited | Structured parsing |
| JSONL and JSON | Yes | JSONL | MassDNS output | JSONL | NDJSON | JSON |
| Brute-force generation | Not yet | Yes | Yes | Yes | Input generation external | No |
| Resolver health validation | Not yet | Health check | External/validation phase | External | No | No |
| Iterative resolution / trace | Not yet | Trace | No | No | Stub | Yes |
| Resume | Not yet | Yes | No | No | No | No |

The matrix is based on the upstream documentation linked above. “Not a primary output concept” avoids claiming a competing implementation cannot perform equivalent work internally; the distinction is dnshunt's user-facing evidence and policy model.

## Repository and implementation audit

### Build and distribution

Original gaps:

- No `go.mod` or `go.sum`; README instructed every user to initialize the module themselves.
- No tests, CI, reproducible build target, release configuration, version injection, security policy, contribution guide, or ignore rules.
- No declared license. This remains an owner decision and should be resolved before broad community adoption.

Implemented:

- Canonical GitHub module path, patched Go toolchain floor, pinned dependencies, static `make build`, version metadata, local integration tests, race/vet checks, CI, and release configuration.

### Correctness and DNS behavior

Original gaps:

- Raw IPv6 resolvers became malformed addresses after `:53` concatenation.
- TXT/MX/CAA/SOA always used TCP instead of using EDNS and falling back only when UDP was actually truncated.
- TCP fallback errors could be ignored and replaced with a misleading empty answer.
- NXDOMAIN answers were discarded before CNAME evidence could be retained.
- Target counts included comments/blank lines, missed a final line without `\n`, and disagreed with processed totals.
- Invalid `-c`, `-rc`, timeout, and resolver settings could panic, deadlock, or create nonsensical behavior.
- Input, writer, flush, and close errors were commonly ignored.
- “q/s” displayed target throughput rather than actual wire queries.

Implemented:

- Validated IPv4/IPv6/hostname endpoints, four DNS transports, [RFC 9715](https://www.rfc-editor.org/info/rfc9715/)'s 1400-byte EDNS recommendation, explicit truncated UDP fallback, bounded response reading, RCODE-aware retries, NXDOMAIN answer preservation, exact normalized counts, strict config validation, error propagation, and true wire-query accounting.

### Performance and resource use

Original gaps:

- Cross-resolver verification was serial, making one target cost approximately the sum of all selected resolver latencies.
- No query-rate control.
- Random resolver selection used global randomness and was not reproducible.
- Progress owned a ticker that was never stopped.

Implemented:

- Concurrent per-job fan-out makes verification latency approximately the slowest selected resolver rather than their sum. The local integration test blocks two resolvers until both requests arrive, proving the fan-out is concurrent rather than timing it heuristically.
- Global rate limiting includes retries and TCP fallback queries; resolver rotation is deterministic; UI tickers are locally owned and stopped; streaming mode keeps input memory constant.

### Security and operations

Original gaps:

- No TLS resolver support, transport metadata, scoped wildcard control, input validation, authorization warning, or security reporting channel.
- ANSI banners and progress could contaminate redirected automation output.

Implemented:

- Certificate-verified DoT/DoH, strict resolver schemes and ports, normalized/validated targets, stdout/stderr separation, TTY-aware progress/color, `NO_COLOR`, structured errors, responsible-use guidance, and `SECURITY.md`.

## Recommended roadmap

### P0 — required for a credible first public release

1. **Choose and add a license.** Apache-2.0 is a strong permissive default for broad CLI/library adoption and includes an explicit patent grant, but only the copyright owner should make this choice.
2. **Publish signed release artifacts and checksums.** The repository now has release automation inputs; connect them to a tag-triggered release workflow and signing identity.
3. **Establish public performance baselines.** Benchmark 10K, 1M, and high-latency target sets; report success rate, p50/p95 latency, packet rate, CPU, and memory. Compare like-for-like and never market MassDNS-scale throughput without evidence.

### P1 — category-leading bug-bounty accuracy

1. **Automatic multi-level wildcard detection.** Group by registrable root, profile likely wildcard parents lazily, cache profiles, expose wildcard roots, and preserve legitimate names that share only part of a wildcard answer pool.
2. **Two-tier resolver trust.** Use fast bulk resolvers for discovery, then revalidate candidates through a smaller trusted set with its own consensus and rate limit. Preserve both phases in JSONL.
3. **Resolver health scoring and quarantine.** Track timeout/error rate, latency, answer disagreement, known-answer baselines, and false-positive NXDOMAIN behavior; stop assigning work to degraded or poisoned resolvers.
4. **Native bruteforce mode.** Stream wordlist × domain generation without storing the Cartesian product, with wildcard profiles initialized before bulk resolution.
5. **CNAME-chain intelligence.** Follow bounded chains, mark terminal NXDOMAIN/SERVFAIL, and emit evidence useful for takeover triage without claiming vulnerability based on DNS alone.

### P2 — ecosystem and scale

1. Resumable scans with input/config fingerprints and append-safe JSONL checkpoints.
2. AXFR attempts, authoritative/all-nameserver mode, trace/iterative resolution, DNSSEC validation state, and lookup modules for MX/NS addresses.
3. Resolver connection reuse and bounded global exchange concurrency for encrypted transports.
4. Output templates, response-code filters, answer-only mode, and optional stable input-order output.
5. A supported Go library API, schema versioning, OpenTelemetry/Prometheus metrics, fuzzing for parser surfaces, and long-running soak tests.
6. Optional CDN/ASN enrichment kept modular so the DNS core remains dependency-light and privacy-conscious.

## Product principles

- **Evidence before claims:** preserve disagreement and provenance; do not collapse uncertainty into “resolved.”
- **Clean pipelines by default:** data on stdout, diagnostics on stderr, JSONL for automation.
- **Safe speed:** expose both concurrency and query rate; count every retry and fallback.
- **One binary, optional complexity:** advanced validation should not require MassDNS, databases, or cloud accounts.
- **Honest benchmarks:** accuracy and resolver friendliness matter as much as peak q/s.
