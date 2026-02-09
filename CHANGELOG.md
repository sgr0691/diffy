# Changelog

All notable changes to this project will be documented in this file.

## [v0.1.0] - 2026-02-09

### Added
- Public exposure detection rules:
  - Security group ingress open to `0.0.0.0/0` or `::/0` on common ports
  - Internet-facing load balancer detection
  - Public IP association enablement detection
- IAM risk detection rules:
  - Policy attachment change detection
  - Policy document change detection (best-effort, path-based)
- Medium/low heuristics:
  - Impactful stateful update signals
  - Network routing/gateway change signals
  - Tag-only low-severity findings
- Resource `change_paths` extraction in the parser and propagation into finding evidence.
- JSON output contract expansion with `changes[]` and `exit_code`.
- Markdown output table expansion with severity and notes columns.
- Additional analyzer/parse/render tests and updated markdown golden snapshots.

### Changed
- README now documents the full v0.1 risk coverage and heuristics.
- CLI output now provides richer context for CI consumers and human reviewers.
