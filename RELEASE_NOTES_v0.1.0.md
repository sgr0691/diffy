# Diffy v0.1.0

Diffy v0.1.0 is ready for OSS launch.

## Highlights

- Terraform plan explain flow with markdown, text, and JSON outputs.
- CI-ready gating with `--fail-on` and deterministic exit behavior.
- Expanded risk coverage for:
  - replacements and deletes (including critical handling for stateful resources)
  - public exposure signals
  - IAM attachment/policy-document changes
  - impactful stateful updates and network-routing changes
  - tag-only low-severity updates
- Richer machine-readable output (`changes[]`, `findings[]`, `threshold`, `decision`, `exit_code`).
- Golden and unit test coverage for parser normalization, risk classification, and renderer behavior.

## What’s Included

- Parser enhancements for per-resource `change_paths`.
- Analyzer enhancements across public exposure, IAM, stateful update, and routing heuristics.
- Renderer updates for markdown severity/notes and expanded JSON payloads.
- Updated examples and expected markdown snapshots.
- Documentation updates in README and changelog.

## Usage

```bash
terraform plan -out=plan.out
diffy explain --from-plan plan.out
diffy explain plan.json --format json
diffy explain plan.json --fail-on high
```

## Notes

- Diffy v0.1.0 is local-only and makes no telemetry calls.
- Risk rules are heuristic and additive; follow-up releases will keep expanding provider/resource coverage.
