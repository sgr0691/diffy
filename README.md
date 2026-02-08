# Diffy

Explain infrastructure diffs in plain English — fast.

Diffy is a tiny OSS CLI that turns Terraform plan output into a human-readable summary with risk flags (replace/delete/public exposure/IAM changes), so reviewers can answer:

> “What’s changing, and how risky is it?”

No dashboards. No agent loops. No auto-remediation. Just clarity.

---

## MVP support (v0.1)

- ✅ Terraform plan JSON (`terraform show -json plan.out`)
- ✅ Markdown / text / JSON output
- ✅ CI-friendly exit codes via `--fail-on`

Planned next:
- Helm diffs, Kubernetes manifests, Pulumi previews (not in v0.1)

---

## Install

### Option A: Go install (dev)
```bash
go install github.com/sgr0691/diffy@latest
```

### Option B: Build from source
```bash
git clone https://github.com/sgr0691/diffy
cd diffy
make build
```

---

## Usage

### 1) Explain a Terraform plan (recommended)
```bash
terraform plan -out=plan.out
diffy explain --from-plan plan.out
```

### 2) Explain a plan JSON directly
```bash
terraform show -json plan.out > plan.json
diffy explain plan.json
```

### Output formats
```bash
diffy explain plan.json --format md
diffy explain plan.json --format text
diffy explain plan.json --format json
```

### CI gating
Fail the build if Diffy finds anything **high** or **critical**:
```bash
diffy explain plan.json --fail-on high
```

Exit codes:
- `0` = no findings at or above the threshold
- `2` = findings at or above the threshold
- `1` = runtime error (bad input, terraform missing, parse failure)

---

## What Diffy flags (v0.1)

- Replacements (`delete + create`) → **high** (or **critical** for stateful resources)
- Deletes → **high** (or **critical** for stateful resources like RDS, S3, ElastiCache, EFS, EKS)

Diffy is intentionally conservative and includes "why flagged" notes.

---

## Quick demo

```bash
# Build
make build

# Run against an example plan
./diffy explain examples/plan/replace.json

# Try different formats
./diffy explain examples/plan/delete_stateful.json --format text
./diffy explain examples/plan/benign_tags_only.json --format json

# CI gating — exits 2 when findings meet threshold
./diffy explain examples/plan/delete_stateful.json --fail-on high; echo "exit: $?"
```

---

## Contributing

PRs welcome. If you’re adding a rule:
- add a sample plan JSON under `examples/`
- add a golden test snapshot under `examples/expected/`

---

## License

MIT
