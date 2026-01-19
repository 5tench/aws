# Method 2 - AWS CLI Drift Check

Compares AWS security group state vs Terraform code in GitHub.

**READ ONLY - no changes made to AWS.**

## Overview

This script performs **bidirectional drift detection** comparing:
- Current AWS security group state
- Your sg.tf file from GitHub

It detects:
- **Additions**: Rules added in AWS console but not in sg.tf
- **Deletions**: Rules in sg.tf that were deleted from AWS console
- **CIDR differences**: Same port/protocol, different IP ranges
- **Structural drift**: Same CIDRs but different rule organization (description grouping)
- **Description differences**: Same rule, different description text

## Limitations

This script **does NOT handle**:
- **Security Group references**: Rules that reference another SG ID instead of CIDR
- **All Traffic rules**: Rules with port `-1` (all traffic)
- **IPv6**: Only processes IPv4 CIDRs (`IpRanges`)
- **Prefix Lists**: Managed prefix list references

Only **CIDR-based rules** are compared.

## Prerequisites

- aws cli
- jq
- awk (gawk)
- AWS credentials configured
- data.tf (contains secret ARN and local mappings)
- sg.tf from GitHub in current directory

## Usage

```bash
# Clone your GitHub repo
git clone <your-repo>
cd <your-repo>

# Copy drift_check.sh to that directory
chmod +x drift_check.sh

# Run with SG ID
./drift_check.sh sg-xxxxxxxxxxxxxxxxx

# Run with debug output
./drift_check.sh --debug sg-xxxxxxxxxxxxxxxxx
```

## Output Files

All output goes to `drift_output/` subfolder (keeps repo clean).

| File | Description | Action |
|------|-------------|--------|
| **sg_generated.tf** | COMPLETE AWS state | **SOURCE OF TRUTH - Use for full sync** |
| **all_changes.txt** | CONSOLIDATED view of all changes | Review all drift types |
| **structural_drift.txt** | Ports with different rule groupings | Check description organization |
| **rules_to_add.tf** | NEW rules in AWS not in sg.tf | Copy these into sg.tf |
| **rules_removed_from_aws.txt** | Rules in sg.tf but not in AWS | Verify - may need removal |
| **rules_cidr_diff.txt** | Same rule, different CIDRs | Update CIDRs in sg.tf |
| **description_diff.txt** | Same rule, different descriptions | Update descriptions |
| drift_report.txt | Full analysis report | Summary |
| drift_summary.json | JSON output | For automation |
| pr_summary.md | PR-ready markdown | For pull requests |
| ip_to_local_map.txt | IP to local.ipX mapping | Debug reference |
| matched_ips.txt | IPs with local refs (sensitive) | Verification only |
| matched_ips_masked.txt | IPs masked (safe to share) | Share with team |


=======================================================================
# awk -F'|' '{n=split($5,a,","); total+=n} END {print total}'  drift_output/aws_cidrs_aggregated.txt should return the combined number of ingress and egress rules from the current aws sg state!***********
=======================================================================


## Workflow

1. **Run the script**
   ```bash
   ./drift_check.sh sg-0a3797a3d81ba3f7f
   ```

2. **Start with all_changes.txt** (consolidated view)
   - Shows all differences in one place
   - Clear side-by-side comparison of GitHub vs AWS

3. **Check rules_to_add.tf**
   - These rules exist in AWS but NOT in your sg.tf
   - Copy the rule blocks into your sg.tf

4. **Check rules_removed_from_aws.txt**
   - These rules are in your sg.tf but NOT in AWS
   - Either remove from sg.tf, or re-add to AWS

5. **Check rules_cidr_diff.txt**
   - Same port/protocol but different CIDRs
   - Update your sg.tf to match AWS

6. **Commit and verify**
   ```bash
   git checkout -b fix-sg-drift
   git add sg.tf
   git commit -m "Sync sg.tf with AWS state"
   terraform plan  # Should show no changes
   ```

7. **Cleanup**
   ```bash
   rm -rf drift_output
   ```

## Example: rules_to_add.tf

```hcl
# =============================================================================
# RULES TO ADD TO sg.tf
# =============================================================================
# These rules exist in AWS but are NOT in your current sg.tf
# Copy these blocks into your sg.tf file
#
# Total rules to add: 2
# =============================================================================

  ingress {
    from_port   = 1527
    to_port     = 1527
    protocol    = "tcp"
    cidr_blocks = [local.ip43, local.ip45, local.ip46]
    description = "Allow Prisma VPN Cidrs"
  }

  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [local.ip41]
    description = "SSM document for beats update"
  }
```

## Example: sg_generated.tf Header

```hcl
# =============================================================================
# SG_GENERATED.TF - Current AWS Security Group State
# =============================================================================
#
# DRIFT STATUS: DRIFT DETECTED
#
# RULES TO ADD (in AWS, not in sg.tf):     3
# RULES REMOVED (in sg.tf, not in AWS):    1  
# RULES WITH CIDR DIFFERENCES:             2
#
# =============================================================================
#                         WHAT TO DO NEXT
# =============================================================================
#
# 1. REVIEW: rules_to_add.tf
#    -> Copy these rule blocks into your sg.tf
#
# 2. REVIEW: rules_removed_from_aws.txt  
#    -> Decide if these should be re-added or removed from sg.tf
#
# 3. REVIEW: rules_cidr_diff.txt
#    -> Update CIDRs in sg.tf to match AWS state
#
# =============================================================================
#                    NEW RULES IN AWS (add to sg.tf)
# =============================================================================
#   ingress: 1527-1527/tcp [local.ip43,local.ip45,local.ip46]
#   egress: 80-80/tcp [local.ip41]
#
```

## How IP Translation Works

1. Script reads data.tf to find: `ip8 = ...["va-profile-cidr1"]`
   - **Includes commented lines** like `# ip1 = ...["devcidr1"]`
2. Fetches secret to get: `va-profile-cidr1 = 10.x.x.x/32`
3. Builds reverse map: `10.x.x.x/32 -> local.ip8`
4. AWS returns real IPs, script translates to local.ipX
5. Unmatched IPs appear as raw quoted strings

### IP Translation Output Files

| File | Contains Real IPs? | Use Case |
|------|-------------------|----------|
| `matched_ips.txt` | **YES** - Sensitive | Verification (keep private) |
| `matched_ips_masked.txt` | **NO** - Safe | Share with team/docs |
| `unmatched_ips.txt` | YES | IPs needing data.tf updates |

**matched_ips.txt** (sensitive):
```
x.x.2.3/32 -> local.ip18 (dbscrp410)
x.x.5.6/32 -> local.ip22 (va-ntp-1)
```

**matched_ips_masked.txt** (safe to share):
```
[masked] -> local.ip18 (dbscrp410)
[masked] -> local.ip22 (va-ntp-1)
```

## Notes

- Platform: Red Hat Enterprise Linux (RHEL)
- Region: Uses your configured AWS region
- Script version: 5.10.0
- All output in `drift_output/` subfolder (repo stays clean)
- CIDRs preserve order from AWS (not sorted alphabetically)
- Rules are sorted by port for better matching
- No actual IPs in matched output (uses local.ipX references)
- Debug mode (`--debug`) dumps diagnostic info at end
- **CIDR aggregation**: Combines all CIDRs per port across rule blocks (handles multiple descriptions)
- **AWS-style rule count**: Shows total rules as AWS counts them (each CIDR = 1 rule)
- **Hardcoded values**: `name` and `description` are pulled from AWS (avoids destroy/recreate)
- **Resource name preservation**: Detects existing sg.tf and reuses resource name

## Changelog

### v5.10.0 (2026-01-13)
- **Fixed**: `name` and `description` now hardcoded from AWS values
  - Prevents destroy/recreate when variables don't match exactly
- **Added**: Preserves existing resource name from sg.tf
  - Script detects `resource "aws_security_group" "NAME"` and reuses it
- **Changed**: Only `vpc_id` remains as variable (standard practice)

### v5.9.0 (2026-01-09)
- **Added**: Structural drift detection
  - Detects when AWS has multiple rule blocks per port with different descriptions
  - But sg.tf combines them into one block (Terraform would show changes)
- **Added**: `structural_drift.txt` output file
- **Changed**: sg_generated.tf now emphasized as SOURCE OF TRUTH
- **Changed**: All messaging updated to recommend using sg_generated.tf for full sync

### v5.8.0 (2026-01-09)
- **Fixed**: sg_generated.tf now creates separate rule blocks per description
  - Previously lumped all CIDRs for same port into one block
  - Now correctly mirrors AWS structure (each description = separate block)
- **Fixed**: Output preserves AWS order (uses `awk '!seen[$0]++'` instead of `sort -u`)

### v5.7.0 (2026-01-09)
- **Added**: Secret key name in matched_ips.txt for verification
  - Now shows: `10.x.x.x/32 -> local.ip18 (dbscrp410)`
- **Added**: `matched_ips_masked.txt` - safe to share version without real IPs
  - Shows: `[masked] -> local.ip18 (dbscrp410)`
- **Added**: Output files ordered by secret key order (matches Secrets Manager view)
- **Fixed**: Secret name extraction for names with multiple hyphens
- **Changed**: Now parses commented lines in data.tf (includes inactive locals)

### v5.6.0 (2026-01-07)
- **Added**: AWS-style rule counting (each CIDR = 1 rule for validation)
  - Now shows both unique port combos AND total rule count (matches AWS console)
  - Helps validate data retrieval and check against AWS SG limits
- **Added**: Limitations notice on startup (SG references, all-traffic rules, IPv6)
- Updated README with Limitations section

### v5.5.0 (2026-01-06)
- **Bug Fix**: CIDR comparison now aggregates ALL CIDRs per port/protocol
  - Previously only compared against first rule block found for a port
  - Now correctly handles multiple rule blocks with different/no descriptions
  - No longer flags CIDRs as "missing" when they exist in another rule block
- Added `aws_cidrs_aggregated.txt` and `github_cidrs_aggregated.txt` intermediate files
- Improved all_changes.txt output shows "(all blocks)" for clarity

### v5.4.0 (2026-01-06)
- All output now goes to `drift_output/` subfolder (keeps repo clean)
- Updated all file path references
- Clearer labeling: "GitHub sg.tf" vs "AWS current"

### v5.3.0 (2025-12-26)
- Added `--debug` flag for diagnostic output
- Added command-line argument parsing

### v5.2.0 (2025-12-26)
- Added `all_changes.txt` consolidated view
- Added `description_diff.txt` for description comparison
- Added `drift_summary.json` for automation
- Added `pr_summary.md` for pull requests

---

# DEMO GUIDE / PRESENTATION

## Slide 1: Title

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│              SECURITY GROUP DRIFT CHECK TOOL                    │
│                        v5.10.0                                  │
│                                                                 │
│     Bidirectional AWS ↔ Terraform Drift Detection               │
│                                                                 │
│                    READ ONLY - Safe to Run                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Slide 2: The Problem

### Manual Security Group Management is Risky

| Problem | Impact |
|---------|--------|
| Console changes not in Terraform | Terraform plan shows unwanted changes |
| Missing rules in sg.tf | Critical access could be removed on apply |
| No visibility into drift | Security gaps go undetected |
| Hard to compare 100+ rules | Human error when syncing |

**We needed a tool to:**
- Compare AWS state vs Terraform code
- Translate IPs to local.ipX references (security)
- Generate ready-to-use Terraform blocks
- Detect ALL types of drift

---

## Slide 3: Solution Overview

```
┌──────────────┐         ┌──────────────┐
│              │         │              │
│     AWS      │ ◄─────► │    sg.tf     │
│   Console    │  COMPARE │   (GitHub)   │
│              │         │              │
└──────────────┘         └──────────────┘
        │                        │
        │    drift_check.sh      │
        │    ───────────────►    │
        │                        │
        ▼                        ▼
┌─────────────────────────────────────────┐
│         drift_output/                   │
│  • sg_generated.tf    ← SOURCE OF TRUTH │
│  • all_changes.txt    ← Summary         │
│  • structural_drift.txt                 │
│  • matched_ips.txt    ← IP verification │
└─────────────────────────────────────────┘
```

---

## Slide 4: Key Features

### What It Detects

| Drift Type | Description |
|------------|-------------|
| **New Rules** | Rules in AWS not in sg.tf |
| **Removed Rules** | Rules in sg.tf not in AWS |
| **CIDR Differences** | Same port, different IPs |
| **Structural Drift** | Same CIDRs, different description groupings |
| **Description Drift** | Same rule, different description text |

### Security Features

- **IP Translation**: Real IPs → local.ipX references
- **Masked Output**: Safe-to-share version without real IPs
- **Secrets Integration**: Uses AWS Secrets Manager
- **READ ONLY**: Never modifies AWS

---

## Slide 5: Demo - Running the Script

### Step 1: Navigate to repo directory
```bash
cd /path/to/terraform-repo
```

### Step 2: Run the script
```bash
./drift_check.sh sg-xxxxidxxxx
```

### Step 3: Watch the output
```
[1/7] Checking prerequisites...
[2/7] Fetching security group from AWS...
[3/7] Loading IP mapping from Secrets Manager...
[4/7] Translating IPs to local.ipX references...
[5/7] Generating Terraform code with local.ipX names...
[6/7] Analyzing rules: AWS vs GitHub sg.tf...
[7/7] Complete
```

---

## Slide 6: Demo - Understanding Output

### Screen Summary
```
=============================================================================
   SUMMARY
=============================================================================

SECURITY GROUP:
  ID:      sg-0a3797a3d81ba3f7f
  Name:    corp-db-security-group-dev-2

RULES ANALYSIS:
  AWS rules:              45
  GitHub sg.tf rules:     42
  Rules to ADD:           3
  Rules REMOVED from AWS: 0
  CIDR differences:       2
  Structural drift:       1

DRIFT STATUS: DRIFT DETECTED

  >>> RECOMMENDED: Use sg_generated.tf as your source of truth <<<
```

---

## Slide 7: Demo - Key Output Files

### File Review Order

| # | File | Purpose |
|---|------|---------|
| 1 | drift_summary.json | Quick status check |
| 2 | **sg_generated.tf** | * Complete AWS state - USE THIS |
| 3 | all_changes.txt | Consolidated drift view |
| 4 | structural_drift.txt | Description grouping issues |
| 5 | matched_ips.txt | Verify IP translations |

### Quick Sync Workflow
```bash
# Copy sg_generated.tf content to sg.tf
cp drift_output/sg_generated.tf sg.tf

# Verify no changes
terraform plan
# Expected: "No changes. Your infrastructure matches the configuration."
```

---

## Slide 8: Demo - IP Translation

### How It Works
```
AWS Returns:     x.x.2.3/32
Script Looks Up: Secrets Manager -> "db-server-1" = x.x.2.3/32
data.tf Has:     ip18 = local.secrets["db-server-1"]
Output Shows:    local.ip18
```

### Verification Files
```
matched_ips.txt (SENSITIVE - keep private):
  x.x.2.3/32 -> local.ip18 (db-server-1)

matched_ips_masked.txt (SAFE to share):
  [masked] -> local.ip18 (db-server-1)
```

---

## Slide 9: Terraform Plan Results

### Success - No Changes
```
$ terraform plan
No changes. Your infrastructure matches the configuration.
```

### Safe - Update In-Place (Orange ~)
```
~ resource "aws_security_group" "sg-dev-2" {
    ~ tags = {
        ~ "Name" = "old-name" -> "new-name"
      }
  }
```
Safe to apply - just updates tags/metadata.

### DANGER - Destroy/Recreate (Red -/+)
```
-/+ resource "aws_security_group" "sg-dev-2" {
      ~ description = "old" -> "new"  # forces replacement
  }
```
**STOP!** Fix the config before applying.

---

## Slide 10: Prerequisites

### Required Files

| File | Purpose |
|------|---------|
| data.tf | Secret ARN + local.ipX mappings |
| sg.tf | Current Terraform security group code |
| providers.tf | AWS provider configuration |
| variables.tf | VPC ID variable |

### Required Tools
```bash
aws --version    # AWS CLI
jq --version     # JSON processor
awk --version    # Text processing
```

### AWS Permissions
- secretsmanager:GetSecretValue
- ec2:DescribeSecurityGroups

---

## Slide 11: Best Practices

### DO

- Run script before any terraform apply
- Use sg_generated.tf as source of truth
- Keep matched_ips.txt private (contains real IPs)
- Share matched_ips_masked.txt in PRs
- Run terraform plan after syncing to verify

### DON'T

- Don't run terraform apply if you see -/+ (destroy/recreate)
- Don't commit secret_values.json (sensitive data)
- Don't skip verification with terraform plan
- Don't manually edit sg_generated.tf (re-run script instead)

---

## Slide 12: Quick Reference

### Command Cheat Sheet
```bash
# Basic run
./drift_check.sh sg-xxxxxxxxx

# Debug mode
./drift_check.sh --debug sg-xxxxxxxxx

# Full sync workflow
./drift_check.sh sg-xxxxxxxxx
cp drift_output/sg_generated.tf sg.tf
terraform plan
# If no changes -> commit and PR
```

### Key Files Location
```
drift_output/
├── sg_generated.tf      ← USE THIS
├── all_changes.txt
├── structural_drift.txt
├── matched_ips.txt      ← SENSITIVE
├── matched_ips_masked.txt ← Safe to share
└── drift_summary.json
```

---

## Slide 13: Questions?

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│                      QUESTIONS?                                 │
│                                                                 │
│     Script Location: method2/drift_check.sh                     │
│     Version: 5.10.0                                             │
│     Mode: READ ONLY (safe to run anytime)                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```
