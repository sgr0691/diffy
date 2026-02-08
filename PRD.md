# PRD: Diffy (v0.1)

## One-liner
A tiny CLI that converts infrastructure diffs (starting with Terraform plans) into a human-readable summary with risk flags.

## Problem
Infra diffs are hard to review:
- Terraform plans are verbose and noisy
- Reviewers miss critical changes (replacements, deletes, public exposure)
- The feedback loop is slow: “ship and pray” or “block everything”

Teams need a fast answer to:
> “What is changing, and how risky is it?”

## Target users
Primary:
- Platform / infra engineers
- SREs
- Senior devs reviewing Terraform changes

Secondary:
- Developers who touch Terraform occasionally
- Teams adopting AI-generated infra code and need guardrails

## MVP scope (v0.1)

### Inputs
Terraform plan output via JSON:
- `terraform plan -out=plan.out`
- `terraform show -json plan.out` (Diffy can run this for you with `--from-plan`)

### Outputs
Plain-English summary + risk flags:

- Counts by action:
  - create / update / delete / replace
- Top high-impact resources
- Findings with severities:
  - info | low | medium | high | critical
- “Why flagged” evidence per finding

### Risk flags (v0.1)
- Replacement (destroy+create)
- Deletes
- Public exposure hints:
  - SG ingress `0.0.0.0/0` / `::/0` on common ports
  - internet-facing LB
  - public IP association enabled
- Data store sensitivity:
  - RDS / Redis / EFS / S3 (deletes and impactful updates)
- IAM changes:
  - policy attachments and (best-effort) policy diffs

### CLI UX
- Install + run in < 10 minutes
- Works locally, no accounts required

Commands:
- `diffy explain <plan.json>`
- `diffy explain --from-plan <plan.out>` (runs `terraform show -json`)
- `diffy explain --format md|text|json` (default: md)
- `diffy explain --fail-on low|medium|high|critical`

### Non-goals (explicit)
- No auto-remediation
- No interactive chat UI
- No autonomous “agent loops”
- No hosted service
- No full Terraform semantics coverage (v0.1 is heuristic + best-effort)

## Success criteria
- A reviewer can understand the plan in < 60 seconds
- Diffy reliably flags obvious “danger” changes in common plans
- Works in CI (deterministic output + useful exit codes)

## v0.2+ ideas (not in MVP)
- Helm diffs (`helm diff`)
- Kubernetes manifest diffs
- Pulumi previews
- GitHub Action wrapper
- PR comment formatter
- “Why replacement happened” hints (best-effort patterns)

## Risks & mitigations
- Terraform JSON structures vary by version/provider
  - Mitigation: schema-tolerant parsing + graceful degradation
- False positives/negatives on public exposure detection
  - Mitigation: conservative severity + confidence + clear evidence

## Open questions
- Severity threshold defaults (recommend: none by default; user opt-in via `--fail-on`)
- Ruleset extensibility (simple config vs code-only in v0.1)