# IaC Drift Detector

This repository holds a small set of read-only AWS drift detection scripts.

The goal is simple: compare what exists in AWS with what is expected from infrastructure code, then produce enough detail to review the drift without making any changes to the account.

Right now the focus is security groups. Over time, this repo can grow into drift checks for other AWS resources as the workflow gets more mature.

## Scripts

The scripts live in `aws/`.

### `drift-check.sh`

Compares one AWS security group against the local Terraform files in the current working directory.

It expects a security group ID at runtime:

```bash
./aws/drift-check.sh sg-xxxxxxxxxxxxxxxxx
```

Optional debug output:

```bash
./aws/drift-check.sh --debug sg-xxxxxxxxxxxxxxxxx
```

The script is read-only. It pulls current security group data from AWS, compares it with `sg.tf`, and writes review files under `drift_output/`.

Expected local inputs:

- `sg.tf`
- `data.tf`
- AWS CLI credentials with read access
- `jq`
- `awk` or `gawk`

### `compare-aws-security-groups.sh`

Compares two AWS security groups directly.

```bash
./aws/compare-aws-security-groups.sh sg-xxxxxxxxxxxxxxxxx sg-yyyyyyyyyyyyyyyyy us-east-1
```

The region argument is optional and defaults to `us-east-1`.

This script is also read-only. It writes audit output to `~/sg_audit_reports`.

## Notes

These scripts do not create, update, or delete AWS resources. They are intended for investigation, review, and pull-request preparation.

Runtime values such as security group IDs, regions, credentials, and Terraform inputs should be passed in or provided by the local environment. The repository should not contain account-specific resource details.
