# TECH_SPEC: Diffy (v0.1)

## Overview
Diffy is a local-only CLI that reads Terraform plan JSON, classifies changes, emits findings, and renders output (md/text/json). v0.1 makes no network calls.

Pipeline:
1) Load plan JSON
2) Normalize resource changes
3) Classify risk (rules)
4) Render output
5) Determine exit code (`--fail-on`)

## Input handling

### Terraform plan -> JSON
Preferred path:
- User provides `plan.out`
- Diffy runs:
  - `terraform show -json plan.out`
- Diffy parses JSON from stdout

Alternate:
- User provides pre-generated `plan.json`

Errors:
- If `--from-plan` is used and terraform is missing, print an actionable error.
- If parsing fails, show the JSON path (when possible) and exit `1`.

## Data model (conceptual)

### ResourceChange
- `address` (e.g., `aws_db_instance.main`)
- `type` (e.g., `aws_db_instance`)
- `provider_name` (optional)
- `actions` (create|update|delete|replace)
- `before` / `after` (optional, as raw JSON for v0.1)
- `change_paths` (optional list of changed attribute paths)

### Finding
- `severity`: info|low|medium|high|critical
- `title`
- `description` ("why flagged")
- `resource_address`
- `evidence` (structured: changed paths / values when available)

## Action derivation
Terraform typically encodes actions at:
- `resource_changes[].change.actions`

Mappings:
- `["create"]` => create
- `["update"]` => update
- `["delete"]` => delete
- `["delete","create"]` => replace

Treat replace as high by default.

## Risk rules (v0.1)

### High/Critical
- Any replace
- Any delete on "stateful" resources
- Public exposure hints:
  - SG ingress `0.0.0.0/0` or `::/0` on common ports
  - LB scheme internet-facing
  - public IP association enabled
- IAM changes:
  - new attachments
  - policy doc changes (best-effort, path-based)

### Medium
- Updates to stateful resources:
  - storage size/type, engine version, instance class, encryption toggles
- Network routing changes (route tables, gateways) when detectable

### Low/Info
- Tag-only changes
- Minor parameter changes

### Stateful resource starter list
AWS (initial):
- `aws_db_instance`, `aws_rds_cluster`, `aws_rds_cluster_instance`
- `aws_elasticache_*`
- `aws_efs_*`
- `aws_s3_bucket` (esp. deletes/public access)
- `aws_eks_cluster` (sensitive updates)

This list expands over time; rules should be additive and test-driven.

## Output formats

### Markdown (default)
- Header: total changes + counts
- Table: top changes
  - action | resource | severity | notes
- Findings grouped by severity
- Each finding includes evidence + "why"

### Text
- Same content, simplified (no tables required)

### JSON
- Machine-readable:
  - counts
  - changes[]
  - findings[]
  - threshold + exit decision

## Exit codes (CI)
- `0`: no findings >= threshold
- `2`: findings >= threshold (e.g., `--fail-on high`)
- `1`: runtime error (invalid input, terraform missing, parse failure)

## CLI implementation (Go recommended)
- Use `cobra` or `urfave/cli/v2`
- Subcommand:
  - `diffy explain [path]`
- Flags:
  - `--from-plan <plan.out>`
  - `--format md|text|json`
  - `--fail-on info|low|medium|high|critical`
  - `--no-terraform` (optional: disallow auto `terraform show -json`)

## Repo layout (suggested)
- `/cmd/diffy` (main)
- `/internal/parse` (terraform json parsing)
- `/internal/analyze` (risk rules + findings)
- `/internal/render` (md/text/json)
- `/examples`
  - `plan/*.json`
  - `expected/*.md`
- `/docs` (optional)

## Testing strategy (credibility)
- Golden tests:
  - plan JSON -> expected markdown snapshot
- Unit tests for:
  - replace detection
  - delete on stateful => high/critical
  - public ingress detection
- Include 3-5 real-ish sample plans under `examples/plan/`

## Security & privacy
- No telemetry.
- No network calls in v0.1.
- If LLM support is added later, it must be opt-in and clearly separated (out of scope for v0.1).