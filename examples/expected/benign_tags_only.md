# Diffy Summary

**2** total changes: 2 to update

## Changes

| Action | Resource | Severity | Notes |
|--------|----------|----------|-------|
| update | aws_instance.web | LOW | Tag-only update detected |
| update | aws_s3_bucket.assets | LOW | Tag-only update detected |

## Findings

### LOW

- **Tag-only update detected** — `aws_instance.web`
  Resource aws_instance.web only changed tags.
  _(action: update, type: aws_instance)_

- **Tag-only update detected** — `aws_s3_bucket.assets`
  Resource aws_s3_bucket.assets only changed tags.
  _(action: update, type: aws_s3_bucket)_
