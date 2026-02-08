# Diffy Summary

**3** total changes: 1 to create, 2 to delete

## Changes

| Action | Resource | Type |
|--------|----------|------|
| delete | aws_db_instance.main | aws_db_instance |
| delete | aws_s3_bucket.logs | aws_s3_bucket |
| create | aws_instance.worker | aws_instance |

## Findings

### CRITICAL

- **Resource deletion detected** — `aws_db_instance.main`
  Stateful resource aws_db_instance.main will be deleted. This will likely cause data loss.
  _(action: delete, type: aws_db_instance)_

- **Resource deletion detected** — `aws_s3_bucket.logs`
  Stateful resource aws_s3_bucket.logs will be deleted. This will likely cause data loss.
  _(action: delete, type: aws_s3_bucket)_

