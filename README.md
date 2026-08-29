# dnshunt

Fast, consensus-aware DNS reconnaissance for bug-bounty and security workflows.

dnshunt resolves large target sets against multiple DNS resolvers in parallel, records the evidence returned by each resolver, and can require independent agreement before a result is accepted. It is built for the point where passive subdomain discovery becomes active validation.

## Why dnshunt

- Cross-resolver consensus: query several distinct resolver endpoints and require `-consensus N` matching observations instead of blindly trusting one answer.
- Parallel verification: resolvers for each target are queried concurrently, avoiding the linear latency cost of serial cross-checks.
- Recon-ready input: stdin, files, and direct targets; URL/port cleanup; IDN conversion; invisible-character removal; validation; and deduplication.
- Reliable DNS behavior: configurable retries, global rate limiting, the current RFC-recommended 1400-byte EDNS default, and automatic TCP fallback for truncated UDP replies.
- Modern transports: UDP, TCP, DNS-over-TLS, and DNS-over-HTTPS resolver endpoints.
- Wildcard filtering: random, multi-probe profiling with an answer pool for round-robin wildcard records.
- Evidence-rich output: stable records, TTLs, response codes, protocol, RTT, attempts, per-resolver answers, observed agreement, and query counts in JSON/JSONL.
- Pipeline-safe UX: successful results on stdout; progress, warnings, and statistics on stderr; automatic color/progress suppression outside a terminal.
- Broad record coverage: A, AAAA, CNAME, NS, MX, TXT, SRV, PTR, SOA, CAA, HTTPS, SVCB, TLSA, DS, DNSKEY, NAPTR, SSHFP, CERT, and ANY.

## Install

Go 1.26.7 or newer (the patch floor avoids known standard-library DNS/TLS/HTTP vulnerabilities):

```bash
go install github.com/codejavu-llc/dnshunt@latest
```

Or build from source without changing the repository:

```bash
git clone https://github.com/codejavu-llc/dnshunt.git
cd dnshunt
make build
./dnshunt -version
```

## Quick start

Resolve a passive subdomain stream and print only verified names:

```bash
subfinder -silent -d example.com |
  dnshunt -silent -rc 3 -consensus 2
```

Query several record types and preserve complete resolver evidence as JSONL:

```bash
dnshunt -l hosts.txt \
  -t A,AAAA,CNAME,NS,MX,TXT \
  -r resolvers.txt \
  -rc 5 -consensus 2 \
  -jsonl -o evidence.jsonl
```

Filter wildcard-backed candidates:

```bash
dnshunt -l candidates.txt \
  -wildcard-domain example.com \
  -wildcard-tests 5 \
  -silent
```

Use encrypted resolvers:

```bash
dnshunt example.com -all \
  -R 'tls://1dot1dot1dot1.cloudflare-dns.com,https://dns.google/dns-query'
```

Reverse-resolve an address range produced by another tool:

```bash
prips 192.0.2.0/24 | dnshunt -t PTR -silent
```

## Resolver formats

Resolver lists accept one endpoint per line. Comma-separated endpoints can be supplied with `-R`.

```text
1.1.1.1
8.8.8.8:53
[2606:4700:4700::1111]:53
udp://resolver.example:53
tcp://resolver.example:53
tls://resolver.example:853
https://resolver.example/dns-query
```

Plain addresses use UDP on port 53. `-tcp` changes plain and `udp://` endpoints to TCP. UDP always retries truncated responses over TCP. DoT certificate verification is enabled; use a resolver hostname whose certificate is valid.

## Consensus and result status

`-rc` selects how many resolvers are queried for each target/type job. `-consensus` selects how many distinct resolvers must return the same answer for it to be accepted.

```bash
# Five observations, at least three must agree.
dnshunt -l targets.txt -r resolvers.txt -rc 5 -consensus 3
```

Statuses in structured output are:

- `NOERROR`: one or more answers met the requested consensus.
- `NXDOMAIN_WITH_ANSWER`: an NXDOMAIN response retained an answer such as a dangling CNAME; useful takeover evidence that many resolvers discard.
- `INCONSISTENT`: answers were observed, but none met the consensus threshold.
- `NXDOMAIN`: the name does not exist according to at least one selected resolver and no answer was accepted.
- `NODATA`: the name exists but the requested record type had no answer.
- `WILDCARD`: the accepted answer matched the scoped wildcard profile.
- `ERROR`: no usable DNS response was received.

Use `-include-failures` with JSONL when investigating disagreement or resolver quality:

```bash
dnshunt -l targets.txt -rc 5 -consensus 3 -jsonl -include-failures |
  jq 'select(.status == "INCONSISTENT")'
```

## Output formats

- `plain` (default): `target [TYPE] answer, answer`
- `text`: a readable record report; add `-v` for per-resolver evidence
- `jsonl`: one complete result per line, safe for streaming and interruption
- `json`: a JSON array, retained for consumers that need a single document

The extension of `-o` selects `jsonl`, `json`, or `text` when `-format` is omitted. `-o` saves a copy while stdout remains available to the next pipeline stage.

## Performance and responsible use

`-c` controls concurrent target/type jobs. Each job fans out to `-rc` resolvers, so the approximate maximum in-flight query count is `c × rc`. Start conservatively and use `-rate-limit` when querying infrastructure you do not operate:

```bash
dnshunt -l large-list.txt -r resolvers.txt -c 250 -rc 3 -rate-limit 2000
```

Default mode deduplicates targets and pre-counts seekable files. `-stream` skips both operations for constant-memory processing of very large or unbounded input.

Only test systems for which you have explicit authorization. High-rate DNS traffic can trigger network controls or abuse reports. Resolver operators may log queries; use resolvers appropriate for the engagement and respect their policies.

## Development

```bash
make check       # formatting, vet, tests, and race detector
make build       # reproducible local binary
make test        # unit and local integration tests
```

The tests run against local UDP/TCP DNS servers and do not depend on public DNS. See [the architecture](docs/ARCHITECTURE.md), [competitive analysis](docs/COMPETITIVE_ANALYSIS.md), and [contribution guide](CONTRIBUTING.md).

## Project direction

dnshunt is intentionally focused on trustworthy active DNS validation rather than passive asset discovery. The research-backed roadmap prioritizes automatic multi-level wildcard discovery, a separate trusted revalidation phase, resolver health scoring/quarantine, and native bruteforce generation. See [competitive analysis and roadmap](docs/COMPETITIVE_ANALYSIS.md#recommended-roadmap).
