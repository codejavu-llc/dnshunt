# Security policy

## Reporting a vulnerability

Please report security vulnerabilities privately to the repository maintainers through GitHub's private vulnerability reporting feature. Do not open a public issue until a fix and disclosure plan are available.

Include the affected version or commit, operating system, reproduction steps, impact, and any suggested mitigation. Avoid including real bug-bounty targets, private resolver logs, credentials, or unrelated personal data.

## Scope

Security reports may include unsafe parsing of untrusted DNS responses, TLS verification bypass, arbitrary file overwrite outside explicitly selected output paths, denial of service from malformed input or replies, secret leakage, command execution, or dependency vulnerabilities with a demonstrated reachable path.

Expected DNS disagreement, public-resolver logging, traffic generated according to user-selected concurrency, and wildcard false positives/negatives without a security boundary bypass are normally reliability issues rather than product vulnerabilities.

## Operational guidance

- Use dnshunt only on targets you are authorized to assess.
- Treat DNS answers and resolver lists as untrusted data.
- Prefer trusted resolvers or resolvers operated for the engagement.
- Use `-rate-limit` and conservative concurrency on shared networks.
- Use DoT or DoH when query confidentiality on the local path is required; resolver operators can still observe queries.
- JSONL output can contain target inventory and resolver evidence. Protect it as engagement data.
