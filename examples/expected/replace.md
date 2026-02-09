# Diffy Summary

**2** total changes: 1 to update, 1 to replace

## Changes

| Action | Resource | Severity | Notes |
|--------|----------|----------|-------|
| replace | aws_instance.web | HIGH | Resource replacement detected |
| update | aws_security_group.web | - | aws_security_group |

## Findings

### HIGH

- **Resource replacement detected** — `aws_instance.web`
  Resource aws_instance.web will be replaced (destroyed and recreated). This may cause downtime or data loss.
  _(action: replace, type: aws_instance)_
