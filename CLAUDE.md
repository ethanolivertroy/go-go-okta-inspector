# CLAUDE.md

## What This Is

Go Go Okta Inspector — a multi-framework compliance audit tool for Okta, written in Go. Single binary, zero runtime dependencies, cross-platform.

Rewrite of [okta-inspector](https://github.com/ethanolivertroy/okta-inspector) (archived Python/Bash version).

## Architecture

```
main.go                    → Entry point, calls cmd.Execute()
cmd/                       → Cobra CLI commands (audit, interactive, report, serve-mcp, config, build, version)
internal/
  app/                     → Application orchestrator (audit pipeline)
  okta/                    → Okta API client (rate limiting, pagination, snapshots)
  engine/                  → Compliance check engine (registry, typed evaluation context)
  framework/               → Framework-specific checks
    fedramp/               → NIST 800-53 controls
    stig/                  → DISA STIG V1R1 (24 requirements)
    irap/                  → Australian ISM controls
    ismap/                 → Japanese ISO 27001:2013
    soc2/                  → Trust Service Criteria (CC6)
    pcidss/                → PCI-DSS 4.0 Requirements 7 & 8
  config/                  → Configuration management
  tui/                     → Interactive terminal UI (Bubble Tea)
  mcp/                     → Model Context Protocol server (JSON-RPC/stdio)
  capabilities/            → Build-time capability restriction system
  report/                  → Report generation (markdown/JSON)
  version/                 → Version/build metadata (set via ldflags)
reference/                 → DISA STIG and IRAP compliance reference documents
testdata/                  → Snapshot fixtures for testing
```

## Build & Run

```bash
make build                 # Build binary with ldflags
make test                  # Run tests with -race
make lint                  # Run golangci-lint
make snapshot              # GoReleaser snapshot build
make tidy                  # go mod tidy
```

## Key Patterns

- **Check registration**: Each framework package has an `init()` that calls `engine.Register()` to register checks
- **EvalContext**: Typed evaluation context passed to checks — includes `Now()` for deterministic timestamps (important for snapshot replay)
- **OktaSnapshot**: Serializes API responses to JSON for offline analysis
- **Rate limiting**: Automatic with exponential backoff in `internal/okta/ratelimit.go`
- **SSRF protection**: Pagination URLs validated in `internal/okta/pagination.go`

## Dependencies

Only 5 direct dependencies:
- `github.com/spf13/cobra` — CLI framework
- `github.com/charmbracelet/bubbletea` — TUI engine
- `github.com/charmbracelet/lipgloss` — Terminal styling
- `github.com/charmbracelet/bubbles` — TUI components
- `gopkg.in/yaml.v3` — Config files

## Priorities

1. **Tests** — Table-driven tests against snapshot fixtures for the compliance check logic. Start with `internal/engine/` and `internal/framework/stig/` since STIG has the most checks (24 requirements, 19 automated). Use `testdata/snapshots/sample_snapshot.json` as a fixture base.

2. **v0.0.1 release** — Cut first release with GoReleaser Pro (`goreleaser release --clean`). Pro license is available. Config is ready in `.goreleaser.yaml` with SBOM generation and changelog grouping.

3. **GitHub Actions CI** — Pipeline for build, test, lint on PR. GoReleaser release on tag push. No CI exists yet.

## Release

- GoReleaser Pro (paid license available)
- Cross-platform: linux/darwin/windows, amd64/arm64
- Binary name: `go-go-okta-inspector`
- Version currently at v0.0.1

## License

GPLv3 (COPYING file)
