# Contributing

Thank you for helping make dnshunt more reliable for the security community.

## Before opening a change

- Keep active testing authorized and use reserved domains/addresses or local fixtures in examples and tests.
- Open an issue for large CLI/schema changes so compatibility and threat-model implications can be discussed.
- Avoid adding network dependencies to tests. The existing integration tests start local UDP and TCP DNS servers.
- Preserve stdout for result data and stderr for diagnostics.

## Development workflow

Go 1.26.7 or newer is required.

```bash
go mod download
make check
make build
```

Changes to DNS behavior should include focused tests for successful answers and relevant failure modes. Changes to structured output must consider backward compatibility and document new fields or statuses. Concurrency changes must pass the race detector.

## Commit and pull-request checklist

- `gofmt -w .` produces no changes.
- `go vet ./...` passes.
- `go test ./...` and `go test -race ./...` pass.
- New flags appear in `dnshunt -h` and the README when user-facing.
- No real customer, program, or private resolver data is committed.
- Performance claims include a reproducible benchmark and environment.
