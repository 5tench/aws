#!/bin/bash
# =============================================================================
# DRIFT CHECK SCRIPT - Compare AWS State vs Terraform Code (GitHub)
# =============================================================================
# READ ONLY - NO CHANGES MADE TO AWS
#
# This script:
#   1. Fetches secret from Secrets Manager to build IP-to-local mapping
#   2. Pulls current security group from AWS by SG ID (read only)
#   3. Translates IPs to local.ipX names
#   4. Compares rules with sg.tf from GitHub (rule-by-rule analysis)
#   5. Compares rule descriptions between AWS and GitHub
#   6. Generates actionable output files in organized folder
#   7. Creates JSON output and PR-ready summary
#
# Platform: Red Hat Enterprise Linux (RHEL)
# Run this script on the TOOLS SERVER
#
# Usage: ./drift_check.sh <security-group-id>
# Example: ./drift_check.sh sg-xxxxxxxxxxxxxxxxx
#
# Prerequisites:
#   - aws cli
#   - jq
#   - awk (gawk)
#   - AWS credentials configured
#   - data.tf (contains secret ARN and local mappings)
#   - sg.tf from GitHub in the current directory
#
# Output Structure:
#   drift_output/  (ALL output in subfolder - keeps repo clean)
#     ├── all_changes.txt         : CONSOLIDATED view of ALL changes needed
#     ├── rules_to_add.tf         : NEW rules to copy into sg.tf
#     ├── sg_generated.tf         : Complete AWS state with summary header
#     ├── rules_removed_from_aws.txt : Rules in sg.tf but not in AWS
#     ├── rules_cidr_diff.txt     : Rules with different CIDRs
#     ├── description_diff.txt    : Rules with different descriptions
#     ├── drift_report.txt        : Summary analysis report
#     ├── drift_summary.json      : JSON output for automation
#     ├── pr_summary.md           : PR-ready summary in markdown
#     └── ip_to_local_map.txt     : IP to local.ipX mapping used
# =============================================================================
# Engineer Contact: cadelery@va.gov

set -e

SCRIPT_VERSION="5.10.0"
CURRENT_DIR="$(pwd)"

# -----------------------------------------------------------------------------
# PARSE COMMAND LINE FLAGS
# -----------------------------------------------------------------------------
DEBUG_MODE=false
SG_ID_ARG=""

for arg in "$@"; do
    case $arg in
        --debug|-d)
            DEBUG_MODE=true
            ;;
        sg-*)
            SG_ID_ARG="$arg"
            ;;
        --help|-h)
            echo "Usage: ./drift_check.sh [--debug] <security-group-id>"
            echo ""
            echo "Options:"
            echo "  --debug, -d    Show detailed diagnostic output at end"
            echo "  --help, -h     Show this help message"
            echo ""
            echo "Example: ./drift_check.sh --debug sg-xxxxxxxxxxxxxxxxx"
            exit 0
            ;;
    esac
done

echo ""
echo "============================================================================="
echo "   DRIFT CHECK v${SCRIPT_VERSION} - READ ONLY (No changes to AWS)"
if [ "$DEBUG_MODE" = true ]; then
    echo "   DEBUG MODE ENABLED"
fi
echo "============================================================================="
echo "   Server: $(hostname) | User: $(whoami)"
echo "   Working Directory: ${CURRENT_DIR}"
echo ""
echo "   LIMITATIONS:"
echo "   - Does NOT handle rules referencing other Security Groups"
echo "   - Does NOT handle 'All Traffic' rules (port -1)"
echo "   - Only compares CIDR-based rules"
echo ""

# -----------------------------------------------------------------------------
# CHECK PREREQUISITES
# -----------------------------------------------------------------------------
echo "[1/7] Checking prerequisites..."
echo ""

PREREQ_FAILED=false

# Check aws cli
if ! command -v aws &> /dev/null; then
    echo "  [FAIL] aws cli is not installed"
    echo "         Install with: sudo yum install awscli"
    PREREQ_FAILED=true
else
    AWS_VERSION=$(aws --version 2>&1 | cut -d' ' -f1)
    echo "  [OK] aws cli found (${AWS_VERSION})"
fi

# Check jq
if ! command -v jq &> /dev/null; then
    echo "  [FAIL] jq is not installed"
    echo "         Install with: sudo yum install jq"
    PREREQ_FAILED=true
else
    JQ_VERSION=$(jq --version 2>&1)
    echo "  [OK] jq found (${JQ_VERSION})"
fi

# Check AWS credentials
if ! aws sts get-caller-identity &> /dev/null; then
    echo "  [FAIL] AWS credentials not configured or invalid"
    echo "         Configure with: aws configure"
    PREREQ_FAILED=true
else
    AWS_ACCOUNT=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null)
    AWS_REGION=$(aws configure get region 2>/dev/null || echo "not-set")
    echo "  [OK] AWS credentials valid (Account: ${AWS_ACCOUNT}, Region: ${AWS_REGION})"
fi

# Check for data.tf
if [ ! -f "data.tf" ]; then
    echo "  [FAIL] data.tf not found in current directory"
    echo "         This file contains the secret ARN and local mappings"
    PREREQ_FAILED=true
else
    echo "  [OK] data.tf found"
fi

# Check for sg.tf from GitHub
if [ ! -f "sg.tf" ]; then
    echo "  [FAIL] sg.tf not found in current directory"
    echo "         Clone your GitHub repo first"
    PREREQ_FAILED=true
else
    echo "  [OK] sg.tf found (from GitHub)"
fi

# Exit if prerequisites failed
if [ "$PREREQ_FAILED" = true ]; then
    echo ""
    echo "============================================================================="
    echo "  PREREQUISITES CHECK FAILED"
    echo "============================================================================="
    echo ""
    echo "Make sure:"
    echo "  1. aws cli and jq are installed"
    echo "  2. AWS credentials are configured"
    echo "  3. data.tf and sg.tf are in the current directory"
    echo ""
    echo "Usage: ./drift_check.sh <security-group-id>"
    echo ""
    exit 1
fi

# -----------------------------------------------------------------------------
# CHECK FOR EXISTING OUTPUT FILES (don't overwrite)
# -----------------------------------------------------------------------------
echo ""
echo "  Checking for existing output files..."

OUTPUT_FILES_EXIST=false
OUTPUT_FILES=""

# Check for output folder
if [ -d "drift_output" ]; then
    OUTPUT_FILES_EXIST=true
    OUTPUT_FILES="${OUTPUT_FILES}    - drift_output/ (folder)\n"
fi

# Check for main output files (now all in drift_output/)
for outfile in drift_output/all_changes.txt drift_output/rules_to_add.tf; do
    if [ -f "$outfile" ]; then
        OUTPUT_FILES_EXIST=true
        OUTPUT_FILES="${OUTPUT_FILES}    - ${outfile}\n"
    fi
done

if [ "$OUTPUT_FILES_EXIST" = true ]; then
    echo ""
    echo "============================================================================="
    echo "  OUTPUT FILES ALREADY EXIST"
    echo "============================================================================="
    echo ""
    echo "The following output files/folders already exist:"
    echo -e "$OUTPUT_FILES"
    echo ""
    echo "To avoid overwriting, please:"
    echo "  1. Remove or rename existing files/folders, OR"
    echo "  2. Run from a clean directory"
    echo ""
    echo "Example: rm -rf drift_output"
    echo ""
    exit 1
fi

echo "  [OK] No existing output files (safe to proceed)"

# Create output directory
mkdir -p drift_output
echo "  [OK] Created drift_output/ folder"

echo ""
echo "  All prerequisites passed"

# -----------------------------------------------------------------------------
# GET SECURITY GROUP ID
# -----------------------------------------------------------------------------
echo ""
if [ -z "$SG_ID_ARG" ]; then
    echo "No security group ID provided."
    read -p "Enter AWS Security Group ID (e.g., sg-xxxxxxxxxxxxxxxxx): " SG_ID
else
    SG_ID="$SG_ID_ARG"
fi

# Validate SG ID format
if [[ ! "$SG_ID" =~ ^sg-[a-f0-9]+$ ]]; then
    echo "ERROR: Invalid security group ID format: ${SG_ID}"
    echo "Expected format: sg-xxxxxxxxxxxxxxxxx"
    exit 1
fi

echo "[2/7] Targeting Security Group: ${SG_ID}"

# -----------------------------------------------------------------------------
# BUILD IP-TO-LOCAL MAPPING FROM SECRETS MANAGER
# -----------------------------------------------------------------------------
echo ""
echo "[3/7] Building IP-to-local mapping from Secrets Manager (READ ONLY)..."
echo ""

# Extract secret ARN from data.tf
SECRET_ARN=$(grep -o 'arn:aws[^"]*' data.tf | head -1)

if [ -z "$SECRET_ARN" ]; then
    echo "  [FAIL] Could not find secret ARN in data.tf"
    echo ""
    echo "  Expected format in data.tf:"
    echo "    arn = \"arn:aws-us-gov:secretsmanager:...\""
    exit 1
fi

# Parse and display ARN components
echo "  -----------------------------------------------------------------------------"
echo "  SECRET DETAILS (extracted from data.tf)"
echo "  -----------------------------------------------------------------------------"
echo "  Full ARN:    ${SECRET_ARN}"

# Extract ARN components for display
ARN_PARTITION=$(echo "$SECRET_ARN" | cut -d':' -f2)
ARN_SERVICE=$(echo "$SECRET_ARN" | cut -d':' -f3)
ARN_REGION=$(echo "$SECRET_ARN" | cut -d':' -f4)
ARN_ACCOUNT=$(echo "$SECRET_ARN" | cut -d':' -f5)
# Secret ARN format: ...secret:name-XXXXXX (6 char random suffix)
# Remove the last hyphen and everything after it (the random suffix)
ARN_SECRET_NAME=$(echo "$SECRET_ARN" | cut -d':' -f7 | sed 's/-[^-]*$//')

echo "  Partition:   ${ARN_PARTITION}"
echo "  Service:     ${ARN_SERVICE}"
echo "  Region:      ${ARN_REGION}"
echo "  Account:     ${ARN_ACCOUNT}"
echo "  Secret Name: ${ARN_SECRET_NAME}"
echo "  -----------------------------------------------------------------------------"
echo ""

# Validate secret exists before fetching (READ ONLY)
echo "  Validating secret exists..."
if ! aws secretsmanager describe-secret --secret-id "$SECRET_ARN" > /dev/null 2>&1; then
    echo "  [FAIL] Secret not found or no access"
    echo "         ARN: ${SECRET_ARN}"
    echo "         Check that the secret exists and you have permission to read it"
    exit 1
fi
echo "  [OK] Secret validated"

# Fetch the secret value (READ ONLY)
echo "  Fetching secret value..."
if ! aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --query 'SecretString' --output text > secret_values.json 2>&1; then
    echo "  [FAIL] Failed to fetch secret value"
    cat secret_values.json
    rm -f secret_values.json
    exit 1
fi

# Count keys in secret
SECRET_KEY_COUNT=$(jq 'keys | length' secret_values.json 2>/dev/null)
echo "  [OK] Secret fetched (${SECRET_KEY_COUNT} keys found)"

# Parse data.tf to build secret_key -> local.ipX mapping
# Format: ip8 = jsondecode(...)["va-profile-cidr1"]
# Also parses commented lines like: # ip1 = jsondecode(...)["devcidr1"]
echo ""
echo "  Building reverse lookup map from data.tf..."

# Count local definitions in data.tf (including commented ones)
LOCAL_COUNT=$(grep -E "ip[0-9]+\s*=" data.tf | wc -l | tr -d ' ')
echo "  Found ${LOCAL_COUNT} local.ipX definitions in data.tf (including commented)"

# Create mapping file: actual_ip -> local.ipX
> drift_output/ip_to_local_map.txt

# Extract all local definitions from data.tf (including commented lines)
# This ensures we can translate IPs even if the local isn't active in terraform
grep -E "ip[0-9]+\s*=" data.tf | while read -r line; do
    # Extract local name (e.g., ip8) - works for both active and commented lines
    LOCAL_NAME=$(echo "$line" | grep -oE "ip[0-9]+" | head -1)

    # Extract secret key (e.g., va-profile-cidr1)
    SECRET_KEY=$(echo "$line" | grep -oE '\["[^"]+"\]' | tr -d '[]"')

    if [ -n "$LOCAL_NAME" ] && [ -n "$SECRET_KEY" ]; then
        # Get the actual IP value from the secret
        ACTUAL_IP=$(jq -r --arg key "$SECRET_KEY" '.[$key] // empty' secret_values.json 2>/dev/null)

        if [ -n "$ACTUAL_IP" ]; then
            # Store: actual_ip|local.ipX|secret_key_name
            echo "${ACTUAL_IP}|local.${LOCAL_NAME}|${SECRET_KEY}" >> drift_output/ip_to_local_map.txt
        fi
    fi
done

MAP_COUNT=$(wc -l < drift_output/ip_to_local_map.txt | tr -d ' ')
echo "  [OK] Built mapping for ${MAP_COUNT} IPs"

# Show mapping summary
echo ""
echo "  -----------------------------------------------------------------------------"
echo "  IP-TO-LOCAL MAPPING PREVIEW (first 5)"
echo "  -----------------------------------------------------------------------------"
head -5 drift_output/ip_to_local_map.txt | while IFS='|' read -r ip local; do
    printf "  %-20s -> %s\n" "[masked]" "$local"
done
if [ "$MAP_COUNT" -gt 5 ]; then
    echo "  ... and $((MAP_COUNT - 5)) more"
fi
echo "  -----------------------------------------------------------------------------"

# -----------------------------------------------------------------------------
# FETCH SECURITY GROUP FROM AWS (READ ONLY)
# -----------------------------------------------------------------------------
echo ""
echo "[4/7] Fetching security group from AWS (READ ONLY)..."
echo ""

# Get security group details from AWS
if ! aws ec2 describe-security-groups --group-ids "$SG_ID" --output json > aws_sg.json 2>&1; then
    echo "  [FAIL] Failed to fetch security group ${SG_ID}"
    echo ""
    echo "  Possible causes:"
    echo "    - Security group does not exist"
    echo "    - SG ID is incorrect"
    echo "    - No permission to describe security groups"
    echo "    - Wrong AWS region"
    echo ""
    cat aws_sg.json
    rm -f aws_sg.json
    exit 1
fi

# Extract the security group from the response
jq '.SecurityGroups[0]' aws_sg.json > aws_sg_detail.json

# Get SG details for display
SG_NAME=$(jq -r '.GroupName' aws_sg_detail.json)
SG_DESC=$(jq -r '.Description' aws_sg_detail.json)
SG_VPC=$(jq -r '.VpcId' aws_sg_detail.json)
SG_OWNER=$(jq -r '.OwnerId' aws_sg_detail.json)

# Count rules
INGRESS_COUNT=$(jq '.IpPermissions | length' aws_sg_detail.json)
EGRESS_COUNT=$(jq '.IpPermissionsEgress | length' aws_sg_detail.json)
INGRESS_CIDR_COUNT=$(jq '[.IpPermissions[].IpRanges[]] | length' aws_sg_detail.json)
EGRESS_CIDR_COUNT=$(jq '[.IpPermissionsEgress[].IpRanges[]] | length' aws_sg_detail.json)
TAG_COUNT=$(jq '.Tags | length' aws_sg_detail.json)

echo "  -----------------------------------------------------------------------------"
echo "  SECURITY GROUP DETAILS (from AWS)"
echo "  -----------------------------------------------------------------------------"
echo "  SG ID:        ${SG_ID}"
echo "  Name:         ${SG_NAME}"
echo "  Description:  ${SG_DESC}"
echo "  VPC ID:       ${SG_VPC}"
echo "  Owner:        ${SG_OWNER}"
echo "  -----------------------------------------------------------------------------"
echo "  RULES SUMMARY"
echo "  -----------------------------------------------------------------------------"
echo "  Ingress:      ${INGRESS_COUNT} rules (${INGRESS_CIDR_COUNT} CIDR entries)"
echo "  Egress:       ${EGRESS_COUNT} rules (${EGRESS_CIDR_COUNT} CIDR entries)"
echo "  Tags:         ${TAG_COUNT}"
echo "  -----------------------------------------------------------------------------"
echo ""

# Show ingress rules preview
echo "  INGRESS RULES PREVIEW:"
jq -r '.IpPermissions[] | "    Port \(.FromPort // "all")-\(.ToPort // "all") \(.IpProtocol) <- \(.IpRanges | length) CIDRs"' aws_sg_detail.json 2>/dev/null | head -5
if [ "$INGRESS_COUNT" -gt 5 ]; then
    echo "    ... and $((INGRESS_COUNT - 5)) more rules"
fi
echo ""

# Show egress rules preview
echo "  EGRESS RULES PREVIEW:"
jq -r '.IpPermissionsEgress[] | "    Port \(.FromPort // "all")-\(.ToPort // "all") \(.IpProtocol) -> \(.IpRanges | length) CIDRs"' aws_sg_detail.json 2>/dev/null | head -5
if [ "$EGRESS_COUNT" -gt 5 ]; then
    echo "    ... and $((EGRESS_COUNT - 5)) more rules"
fi
echo "  -----------------------------------------------------------------------------"
echo ""
echo "  [OK] Security group fetched"

# -----------------------------------------------------------------------------
# CONFIRMATION PROMPT
# -----------------------------------------------------------------------------
echo ""
echo "============================================================================="
echo "   VERIFICATION - Please confirm before proceeding"
echo "============================================================================="
echo ""
echo "   You are about to compare:"
echo ""
echo "   AWS Security Group:"
echo "     ID:   ${SG_ID}"
echo "     Name: ${SG_NAME}"
echo "     VPC:  ${SG_VPC}"
echo ""
echo "   Using Secret:"
echo "     ${ARN_SECRET_NAME} (${MAP_COUNT} IP mappings)"
echo ""
echo "   Against GitHub file:"
echo "     sg.tf (in current directory)"
echo ""
echo "============================================================================="
echo ""
read -p "Does this look correct? Continue? (y/n): " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo ""
    echo "Aborted by user."
    rm -f secret_values.json aws_sg.json aws_sg_detail.json ip_to_local_map.txt
    exit 0
fi
echo ""

# -----------------------------------------------------------------------------
# INITIALIZE TRACKING FILES
# -----------------------------------------------------------------------------
# Track matched and unmatched IPs for summary
# Two versions: one with real IPs (for verification), one masked (safe to share)
> drift_output/matched_ips.txt
> drift_output/matched_ips_masked.txt
> drift_output/unmatched_ips.txt
MATCH_COUNT=0
UNMATCH_COUNT=0

# -----------------------------------------------------------------------------
# FUNCTION: Translate IP to local name (with tracking)
# -----------------------------------------------------------------------------
translate_ip() {
    local ip="$1"
    local result=""
    local secret_key=""

    # Try to find the IP in our mapping (format: ip|local.ipX|secret_key)
    result=$(grep "^${ip}|" drift_output/ip_to_local_map.txt 2>/dev/null | cut -d'|' -f2 || true)
    secret_key=$(grep "^${ip}|" drift_output/ip_to_local_map.txt 2>/dev/null | cut -d'|' -f3 || true)

    if [ -n "$result" ]; then
        # Success - found a match
        # Only log unique IPs (check if already logged)
        if ! grep -qF "$ip -> $result" drift_output/matched_ips.txt 2>/dev/null; then
            # Full version with actual IP (sensitive - do not share)
            echo "$ip -> $result ($secret_key)" >> drift_output/matched_ips.txt
            # Masked version (safe to share)
            echo "[masked] -> $result ($secret_key)" >> drift_output/matched_ips_masked.txt
        fi
        echo "$result"
    else
        # Failed to match - track unique unmatched IPs
        if ! grep -qF "$ip" drift_output/unmatched_ips.txt 2>/dev/null; then
            echo "$ip" >> drift_output/unmatched_ips.txt
        fi
        # Return the raw IP properly quoted for terraform
        echo "\"${ip}\""
    fi
}

# -----------------------------------------------------------------------------
# GENERATE .TF FILE WITH LOCAL NAMES (NOT REAL IPs)
# -----------------------------------------------------------------------------
echo ""
echo "[5/7] Generating Terraform code with local.ipX names..."
echo ""

# Create a clean resource name from the SG name
RESOURCE_NAME=$(echo "$SG_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g' | sed 's/^-//' | sed 's/-$//')

# Try to extract existing resource name from sg.tf to preserve it (avoids destroy/recreate)
EXISTING_RESOURCE_NAME=$(grep -oP 'resource\s+"aws_security_group"\s+"\K[^"]+' sg.tf 2>/dev/null | head -1)
if [ -n "$EXISTING_RESOURCE_NAME" ]; then
    echo "  Found existing resource name in sg.tf: ${EXISTING_RESOURCE_NAME}"
    echo "  Using existing name to avoid destroy/recreate"
    RESOURCE_NAME="$EXISTING_RESOURCE_NAME"
else
    echo "  No existing sg.tf found, using generated name: ${RESOURCE_NAME}"
fi

# Escape any quotes in AWS values for safe embedding in HCL
SG_NAME_ESCAPED=$(echo "$SG_NAME" | sed 's/"/\\"/g')
SG_DESC_ESCAPED=$(echo "$SG_DESC" | sed 's/"/\\"/g')

# Generate terraform code to temp file first (header added after diff)
# Using HARDCODED values from AWS to avoid destroy/recreate issues
cat > drift_output/sg_temp_body.tf << TFHEADER
resource "aws_security_group" "${RESOURCE_NAME}" {
  name        = "${SG_NAME_ESCAPED}"
  description = "${SG_DESC_ESCAPED}"
  vpc_id      = var.vpc_id

  # INGRESS RULES
  # ================================================================================

TFHEADER

# Process INGRESS rules - SORTED by from_port, then to_port, then protocol
# IMPORTANT: Group CIDRs by description - AWS allows same port with different descriptions
jq -c '.IpPermissions | sort_by(.FromPort, .ToPort, .IpProtocol) | .[]?' aws_sg_detail.json 2>/dev/null | while read -r rule; do
    FROM_PORT=$(echo "$rule" | jq -r '.FromPort // 0')
    TO_PORT=$(echo "$rule" | jq -r '.ToPort // 0')
    PROTOCOL=$(echo "$rule" | jq -r '.IpProtocol')

    # Get unique descriptions for this rule (preserve AWS order, not sorted)
    # Using awk to get unique values while preserving insertion order
    echo "$rule" | jq -r '.IpRanges[]? | .Description // ""' | awk '!seen[$0]++' | while read -r DESC; do
        # Get all CIDRs with THIS description (preserve order from AWS)
        CIDR_LIST=""
        while read -r cidr; do
            LOCAL_REF=$(translate_ip "$cidr")
            if [ -n "$CIDR_LIST" ]; then
                CIDR_LIST="${CIDR_LIST}\n${LOCAL_REF}"
            else
                CIDR_LIST="${LOCAL_REF}"
            fi
        done < <(echo "$rule" | jq -r --arg desc "$DESC" '.IpRanges[]? | select((.Description // "") == $desc) | .CidrIp')
        
        # Join CIDRs with comma (preserve order, no sort)
        CIDRS=$(echo -e "$CIDR_LIST" | grep -v '^$' | tr '\n' ',' | sed 's/,$//' | sed 's/,/, /g')
        
        # Skip if no CIDRs (shouldn't happen but safety check)
        if [ -n "$CIDRS" ]; then
            cat >> drift_output/sg_temp_body.tf << INGRESSBLOCK
  ingress {
    from_port   = ${FROM_PORT}
    to_port     = ${TO_PORT}
    protocol    = "${PROTOCOL}"
    cidr_blocks = [${CIDRS}]
    description = "${DESC}"
  }

INGRESSBLOCK
        fi
    done
done

# Add egress section header
cat >> drift_output/sg_temp_body.tf << EGRESSHEADER
# EGRESS RULES
# ================================================================================

EGRESSHEADER

# Process EGRESS rules - SORTED by from_port, then to_port, then protocol
# IMPORTANT: Group CIDRs by description - AWS allows same port with different descriptions
jq -c '.IpPermissionsEgress | sort_by(.FromPort, .ToPort, .IpProtocol) | .[]?' aws_sg_detail.json 2>/dev/null | while read -r rule; do
    FROM_PORT=$(echo "$rule" | jq -r '.FromPort // 0')
    TO_PORT=$(echo "$rule" | jq -r '.ToPort // 0')
    PROTOCOL=$(echo "$rule" | jq -r '.IpProtocol')

    # Get unique descriptions for this rule (preserve AWS order, not sorted)
    echo "$rule" | jq -r '.IpRanges[]? | .Description // ""' | awk '!seen[$0]++' | while read -r DESC; do
        # Get all CIDRs with THIS description (preserve order from AWS)
        CIDR_LIST=""
        while read -r cidr; do
            LOCAL_REF=$(translate_ip "$cidr")
            if [ -n "$CIDR_LIST" ]; then
                CIDR_LIST="${CIDR_LIST}\n${LOCAL_REF}"
            else
                CIDR_LIST="${LOCAL_REF}"
            fi
        done < <(echo "$rule" | jq -r --arg desc "$DESC" '.IpRanges[]? | select((.Description // "") == $desc) | .CidrIp')
        
        # Join CIDRs with comma (preserve order, no sort)
        CIDRS=$(echo -e "$CIDR_LIST" | grep -v '^$' | tr '\n' ',' | sed 's/,$//' | sed 's/,/, /g')
        
        # Skip if no CIDRs (might be security group references)
        if [ -n "$CIDRS" ]; then
            cat >> drift_output/sg_temp_body.tf << EGRESSBLOCK
  egress {
    from_port   = ${FROM_PORT}
    to_port     = ${TO_PORT}
    protocol    = "${PROTOCOL}"
    cidr_blocks = [${CIDRS}]
    description = "${DESC}"
  }

EGRESSBLOCK
        fi
    done
done

# Add tags section
cat >> drift_output/sg_temp_body.tf << TAGHEADER
  # TAGS
  # ================================================================================
TAGHEADER

TAGS=$(jq '.Tags // []' aws_sg_detail.json)
if [ "$TAGS" != "[]" ] && [ "$TAGS" != "null" ]; then
    echo "  tags = {" >> drift_output/sg_temp_body.tf
    jq -r '.Tags[]? | "    \"\(.Key)\" = \"\(.Value)\""' aws_sg_detail.json >> drift_output/sg_temp_body.tf 2>/dev/null
    echo "  }" >> drift_output/sg_temp_body.tf
fi

# Close the resource block
echo "}" >> drift_output/sg_temp_body.tf

echo "  [OK] Generated terraform code (body)"

# -----------------------------------------------------------------------------
# REORDER MATCHED IPs TO MATCH SECRET KEY ORDER
# -----------------------------------------------------------------------------
# Reorder matched_ips.txt to match the order of keys in the secret
# This makes verification easier - matches the order you see in Secrets Manager
if [ -s drift_output/matched_ips.txt ]; then
    echo "  Reordering matched IPs to match secret key order..."
    
    # Save original files
    cp drift_output/matched_ips.txt drift_output/matched_ips_unsorted.txt
    cp drift_output/matched_ips_masked.txt drift_output/matched_ips_masked_unsorted.txt
    
    # Clear output files
    > drift_output/matched_ips.txt
    > drift_output/matched_ips_masked.txt
    
    # Get secret keys in original order and reorder matched files accordingly
    # Using to_entries preserves the order from the secret (keys[] would sort alphabetically)
    if jq -r 'to_entries[] | .key' secret_values.json 2>/dev/null | while read -r secret_key; do
        # Find any line with this secret key and append to output (preserves secret order)
        grep "($secret_key)$" drift_output/matched_ips_unsorted.txt >> drift_output/matched_ips.txt 2>/dev/null || true
        grep "($secret_key)$" drift_output/matched_ips_masked_unsorted.txt >> drift_output/matched_ips_masked.txt 2>/dev/null || true
    done; then
        echo "  [OK] Reordered to match secret key order"
    else
        # Fallback: restore original files if reordering failed
        echo "  [WARN] Reordering failed, keeping original order"
        cp drift_output/matched_ips_unsorted.txt drift_output/matched_ips.txt
        cp drift_output/matched_ips_masked_unsorted.txt drift_output/matched_ips_masked.txt
    fi
    
    # Clean up temp files
    rm -f drift_output/matched_ips_unsorted.txt drift_output/matched_ips_masked_unsorted.txt
fi

# -----------------------------------------------------------------------------
# TRANSLATION SUMMARY
# -----------------------------------------------------------------------------
echo ""
echo "  -----------------------------------------------------------------------------"
echo "  IP TRANSLATION SUMMARY"
echo "  -----------------------------------------------------------------------------"

MATCH_COUNT=$(wc -l < drift_output/matched_ips.txt 2>/dev/null | tr -d ' ' || echo "0")
UNMATCH_COUNT=$(wc -l < drift_output/unmatched_ips.txt 2>/dev/null | tr -d ' ' || echo "0")
TOTAL_IPS=$((MATCH_COUNT + UNMATCH_COUNT))

echo "  Total IPs processed:  ${TOTAL_IPS}"
echo "  Successfully matched: ${MATCH_COUNT}"
echo "  Unmatched (raw IPs):  ${UNMATCH_COUNT}"
echo ""

if [ "$UNMATCH_COUNT" -gt 0 ]; then
    echo "  [WARNING] Some IPs could not be translated to local.ipX"
    echo ""
    echo "  UNMATCHED IPs (showing raw IP in output):"
    echo "  -----------------------------------------------------------------------------"
    cat drift_output/unmatched_ips.txt | while read -r ip; do
        echo "    - [masked IP] not found in data.tf locals"
    done
    echo "  -----------------------------------------------------------------------------"
    echo ""
    echo "  These IPs exist in AWS but have no matching local.ipX in data.tf"
    echo "  They may be:"
    echo "    - New IPs added directly in AWS (not in Terraform)"
    echo "    - IPs from a different secret"
    echo "    - Commented out locals in data.tf"
    echo ""
else
    echo "  [OK] All IPs successfully translated to local.ipX names"
fi
echo "  -----------------------------------------------------------------------------"

# -----------------------------------------------------------------------------
# COMPARE WITH GITHUB sg.tf - RULE BY RULE ANALYSIS
# -----------------------------------------------------------------------------
echo ""
echo "[6/7] Analyzing rules: AWS vs GitHub sg.tf..."
echo ""

# Parse sg.tf to extract rules into a comparable format
# Format: direction|from_port|to_port|protocol|sorted_cidrs|description
echo "  Parsing sg.tf..."

> drift_output/github_rules.txt
> drift_output/github_rules_detail.txt

# Extract ingress rules from sg.tf
awk '
/ingress\s*\{/,/\}/ {
    if (/from_port/) { gsub(/[^0-9]/, "", $0); from_port = $0 }
    if (/to_port/) { gsub(/[^0-9]/, "", $0); to_port = $0 }
    if (/protocol\s*=/) { gsub(/.*protocol\s*=\s*"/, "", $0); gsub(/".*/, "", $0); protocol = $0 }
    if (/cidr_blocks\s*=/) {
        gsub(/.*cidr_blocks\s*=\s*\[/, "", $0);
        gsub(/\].*/, "", $0);
        gsub(/\s+/, "", $0);
        cidrs = $0
    }
    if (/description\s*=/) {
        gsub(/.*description\s*=\s*"/, "", $0);
        gsub(/".*/, "", $0);
        desc = $0
    }
    if (/^\s*\}/) {
        if (from_port != "" && protocol != "") {
            # Sort CIDRs for consistent comparison
            n = split(cidrs, arr, ",")
            for (i = 1; i <= n; i++) sorted[i] = arr[i]
            asort(sorted)
            sorted_cidrs = ""
            for (i = 1; i <= n; i++) {
                if (sorted_cidrs != "") sorted_cidrs = sorted_cidrs ","
                sorted_cidrs = sorted_cidrs sorted[i]
            }
            key = "ingress|" from_port "|" to_port "|" protocol
            print key "|" sorted_cidrs
            print key "|" sorted_cidrs "|" desc >> "drift_output/github_rules_detail.txt"
        }
        from_port = ""; to_port = ""; protocol = ""; cidrs = ""; desc = ""
        delete sorted
    }
}' sg.tf >> drift_output/github_rules.txt

# Extract egress rules from sg.tf
awk '
/egress\s*\{/,/\}/ {
    if (/from_port/) { gsub(/[^0-9]/, "", $0); from_port = $0 }
    if (/to_port/) { gsub(/[^0-9]/, "", $0); to_port = $0 }
    if (/protocol\s*=/) { gsub(/.*protocol\s*=\s*"/, "", $0); gsub(/".*/, "", $0); protocol = $0 }
    if (/cidr_blocks\s*=/) {
        gsub(/.*cidr_blocks\s*=\s*\[/, "", $0);
        gsub(/\].*/, "", $0);
        gsub(/\s+/, "", $0);
        cidrs = $0
    }
    if (/description\s*=/) {
        gsub(/.*description\s*=\s*"/, "", $0);
        gsub(/".*/, "", $0);
        desc = $0
    }
    if (/^\s*\}/) {
        if (from_port != "" && protocol != "") {
            n = split(cidrs, arr, ",")
            for (i = 1; i <= n; i++) sorted[i] = arr[i]
            asort(sorted)
            sorted_cidrs = ""
            for (i = 1; i <= n; i++) {
                if (sorted_cidrs != "") sorted_cidrs = sorted_cidrs ","
                sorted_cidrs = sorted_cidrs sorted[i]
            }
            key = "egress|" from_port "|" to_port "|" protocol
            print key "|" sorted_cidrs
            print key "|" sorted_cidrs "|" desc >> "drift_output/github_rules_detail.txt"
        }
        from_port = ""; to_port = ""; protocol = ""; cidrs = ""; desc = ""
        delete sorted
    }
}' sg.tf >> drift_output/github_rules.txt

GITHUB_RULE_COUNT=$(wc -l < drift_output/github_rules.txt | tr -d ' ')
echo "  [OK] Found ${GITHUB_RULE_COUNT} rules in sg.tf"

# Parse AWS rules from sg_temp_body.tf (already has local.ipX names)
echo "  Parsing AWS rules from sg_temp_body.tf..."

> drift_output/aws_rules.txt
> drift_output/aws_rules_detail.txt

# Extract ingress rules from generated AWS tf
awk '
/ingress\s*\{/,/\}/ {
    if (/from_port/) { gsub(/[^0-9]/, "", $0); from_port = $0 }
    if (/to_port/) { gsub(/[^0-9]/, "", $0); to_port = $0 }
    if (/protocol\s*=/) { gsub(/.*protocol\s*=\s*"/, "", $0); gsub(/".*/, "", $0); protocol = $0 }
    if (/cidr_blocks\s*=/) {
        gsub(/.*cidr_blocks\s*=\s*\[/, "", $0);
        gsub(/\].*/, "", $0);
        gsub(/\s+/, "", $0);
        cidrs = $0
    }
    if (/description\s*=/) {
        gsub(/.*description\s*=\s*"/, "", $0);
        gsub(/".*/, "", $0);
        desc = $0
    }
    if (/^\s*\}/) {
        if (from_port != "" && protocol != "") {
            n = split(cidrs, arr, ",")
            for (i = 1; i <= n; i++) sorted[i] = arr[i]
            asort(sorted)
            sorted_cidrs = ""
            for (i = 1; i <= n; i++) {
                if (sorted_cidrs != "") sorted_cidrs = sorted_cidrs ","
                sorted_cidrs = sorted_cidrs sorted[i]
            }
            key = "ingress|" from_port "|" to_port "|" protocol
            print key "|" sorted_cidrs
            print key "|" sorted_cidrs "|" desc >> "drift_output/aws_rules_detail.txt"
        }
        from_port = ""; to_port = ""; protocol = ""; cidrs = ""; desc = ""
        delete sorted
    }
}' drift_output/sg_temp_body.tf >> drift_output/aws_rules.txt

# Extract egress rules from generated AWS tf
awk '
/egress\s*\{/,/\}/ {
    if (/from_port/) { gsub(/[^0-9]/, "", $0); from_port = $0 }
    if (/to_port/) { gsub(/[^0-9]/, "", $0); to_port = $0 }
    if (/protocol\s*=/) { gsub(/.*protocol\s*=\s*"/, "", $0); gsub(/".*/, "", $0); protocol = $0 }
    if (/cidr_blocks\s*=/) {
        gsub(/.*cidr_blocks\s*=\s*\[/, "", $0);
        gsub(/\].*/, "", $0);
        gsub(/\s+/, "", $0);
        cidrs = $0
    }
    if (/description\s*=/) {
        gsub(/.*description\s*=\s*"/, "", $0);
        gsub(/".*/, "", $0);
        desc = $0
    }
    if (/^\s*\}/) {
        if (from_port != "" && protocol != "") {
            n = split(cidrs, arr, ",")
            for (i = 1; i <= n; i++) sorted[i] = arr[i]
            asort(sorted)
            sorted_cidrs = ""
            for (i = 1; i <= n; i++) {
                if (sorted_cidrs != "") sorted_cidrs = sorted_cidrs ","
                sorted_cidrs = sorted_cidrs sorted[i]
            }
            key = "egress|" from_port "|" to_port "|" protocol
            print key "|" sorted_cidrs
            print key "|" sorted_cidrs "|" desc >> "drift_output/aws_rules_detail.txt"
        }
        from_port = ""; to_port = ""; protocol = ""; cidrs = ""; desc = ""
        delete sorted
    }
}' drift_output/sg_temp_body.tf >> drift_output/aws_rules.txt

AWS_RULE_COUNT=$(wc -l < drift_output/aws_rules.txt | tr -d ' ')
echo "  [OK] Found ${AWS_RULE_COUNT} rules in AWS"

# Compare rules
echo "  Comparing rules..."

# -----------------------------------------------------------------------------
# AGGREGATE CIDRs PER PORT/PROTOCOL (regardless of description)
# This handles cases where same port has multiple rule blocks with different descriptions
# -----------------------------------------------------------------------------
echo "  Aggregating CIDRs per port/protocol..."

# Aggregate AWS CIDRs per port
> drift_output/aws_cidrs_aggregated.txt
awk -F'|' '{
    key = $1 "|" $2 "|" $3 "|" $4
    n = split($5, cidrs, ",")
    for (i = 1; i <= n; i++) {
        cidr = cidrs[i]
        gsub(/^ +| +$/, "", cidr)  # trim whitespace
        if (cidr != "") {
            seen[key, cidr] = 1
            keys[key] = 1
        }
    }
}
END {
    for (key in keys) {
        cidrs_str = ""
        for (combo in seen) {
            split(combo, parts, SUBSEP)
            if (parts[1] == key) {
                if (cidrs_str != "") cidrs_str = cidrs_str ","
                cidrs_str = cidrs_str parts[2]
            }
        }
        print key "|" cidrs_str
    }
}' drift_output/aws_rules.txt | while IFS='|' read -r dir fp tp proto cidrs; do
    # Sort CIDRs for consistent comparison
    sorted_cidrs=$(echo "$cidrs" | tr ',' '\n' | sort | tr '\n' ',' | sed 's/,$//')
    echo "${dir}|${fp}|${tp}|${proto}|${sorted_cidrs}"
done > drift_output/aws_cidrs_aggregated.txt

# Aggregate GitHub CIDRs per port
> drift_output/github_cidrs_aggregated.txt
awk -F'|' '{
    key = $1 "|" $2 "|" $3 "|" $4
    n = split($5, cidrs, ",")
    for (i = 1; i <= n; i++) {
        cidr = cidrs[i]
        gsub(/^ +| +$/, "", cidr)  # trim whitespace
        if (cidr != "") {
            seen[key, cidr] = 1
            keys[key] = 1
        }
    }
}
END {
    for (key in keys) {
        cidrs_str = ""
        for (combo in seen) {
            split(combo, parts, SUBSEP)
            if (parts[1] == key) {
                if (cidrs_str != "") cidrs_str = cidrs_str ","
                cidrs_str = cidrs_str parts[2]
            }
        }
        print key "|" cidrs_str
    }
}' drift_output/github_rules.txt | while IFS='|' read -r dir fp tp proto cidrs; do
    # Sort CIDRs for consistent comparison
    sorted_cidrs=$(echo "$cidrs" | tr ',' '\n' | sort | tr '\n' ',' | sed 's/,$//')
    echo "${dir}|${fp}|${tp}|${proto}|${sorted_cidrs}"
done > drift_output/github_cidrs_aggregated.txt

# -----------------------------------------------------------------------------
# COMPARE AGGREGATED CIDRs
# -----------------------------------------------------------------------------

# Find rules in AWS but NOT in GitHub (need to ADD these)
> drift_output/rules_to_add_keys.txt
> drift_output/cidr_diff_aws.txt
while IFS='|' read -r direction from_port to_port protocol aws_cidrs; do
    key="${direction}|${from_port}|${to_port}|${protocol}"
    
    # Get aggregated GitHub CIDRs for this port
    github_cidrs=$(grep "^${key}|" drift_output/github_cidrs_aggregated.txt 2>/dev/null | cut -d'|' -f5 | head -1)
    
    if [ -z "$github_cidrs" ]; then
        # Port doesn't exist in GitHub at all - completely new rule
        echo "${key}|${aws_cidrs}" >> drift_output/rules_to_add_keys.txt
    elif [ "$aws_cidrs" != "$github_cidrs" ]; then
        # Same port exists but CIDRs differ - track for CIDR diff
        echo "${key}|${aws_cidrs}" >> drift_output/cidr_diff_aws.txt
    fi
done < drift_output/aws_cidrs_aggregated.txt

# Find rules in GitHub but NOT in AWS (may have been removed)
> drift_output/rules_removed_keys.txt
> drift_output/cidr_diff_github.txt
while IFS='|' read -r direction from_port to_port protocol github_cidrs; do
    key="${direction}|${from_port}|${to_port}|${protocol}"
    
    # Get aggregated AWS CIDRs for this port
    aws_cidrs=$(grep "^${key}|" drift_output/aws_cidrs_aggregated.txt 2>/dev/null | cut -d'|' -f5 | head -1)
    
    if [ -z "$aws_cidrs" ]; then
        # Port doesn't exist in AWS at all - rule was removed
        echo "${key}|${github_cidrs}" >> drift_output/rules_removed_keys.txt
    elif [ "$github_cidrs" != "$aws_cidrs" ]; then
        # Already tracked in cidr_diff_aws, just track GitHub side
        echo "${key}|${github_cidrs}" >> drift_output/cidr_diff_github.txt
    fi
done < drift_output/github_cidrs_aggregated.txt

RULES_TO_ADD=$(wc -l < drift_output/rules_to_add_keys.txt 2>/dev/null | tr -d ' ' || echo "0")
RULES_REMOVED=$(wc -l < drift_output/rules_removed_keys.txt 2>/dev/null | tr -d ' ' || echo "0")
CIDR_DIFF_COUNT=$(wc -l < drift_output/cidr_diff_aws.txt 2>/dev/null | tr -d ' ' || echo "0")

# -----------------------------------------------------------------------------
# STRUCTURAL DRIFT DETECTION (different number of rule blocks per port)
# -----------------------------------------------------------------------------
# Count rule blocks (NOT aggregated) per port/protocol for both sides
# AWS has separate rules per description, sg.tf might combine them
echo "  Checking for structural drift (description grouping differences)..."

> drift_output/structural_drift.txt
STRUCTURAL_DRIFT_COUNT=0

# For each unique port/protocol, compare number of rule blocks
while IFS='|' read -r direction from_port to_port protocol _; do
    key="${direction}|${from_port}|${to_port}|${protocol}"
    
    # Count AWS rule blocks for this port (from non-aggregated file)
    aws_block_count=$(grep -c "^${key}|" drift_output/aws_rules.txt 2>/dev/null || echo "0")
    
    # Count GitHub rule blocks for this port (from non-aggregated file)
    github_block_count=$(grep -c "^${key}|" drift_output/github_rules.txt 2>/dev/null || echo "0")
    
    if [ "$aws_block_count" != "$github_block_count" ] && [ "$aws_block_count" -gt 0 ] && [ "$github_block_count" -gt 0 ]; then
        STRUCTURAL_DRIFT_COUNT=$((STRUCTURAL_DRIFT_COUNT + 1))
        echo "${direction}: port ${from_port}-${to_port}/${protocol}" >> drift_output/structural_drift.txt
        echo "  AWS has ${aws_block_count} rule block(s) with different descriptions" >> drift_output/structural_drift.txt
        echo "  sg.tf has ${github_block_count} rule block(s)" >> drift_output/structural_drift.txt
        echo "  -> Terraform will show changes even if CIDRs match!" >> drift_output/structural_drift.txt
        echo "" >> drift_output/structural_drift.txt
    fi
done < drift_output/aws_cidrs_aggregated.txt

if [ "$STRUCTURAL_DRIFT_COUNT" -gt 0 ]; then
    echo "  [!] Found ${STRUCTURAL_DRIFT_COUNT} ports with structural differences"
else
    echo "  [OK] No structural drift detected"
fi

# Calculate AWS-style rule counts (each CIDR = 1 rule)
AWS_TOTAL_RULES=$(awk -F'|' '{n=split($5,a,","); total+=n} END {print total}' drift_output/aws_cidrs_aggregated.txt 2>/dev/null || echo "0")
GITHUB_TOTAL_RULES=$(awk -F'|' '{n=split($5,a,","); total+=n} END {print total}' drift_output/github_cidrs_aggregated.txt 2>/dev/null || echo "0")

echo ""
echo "  -----------------------------------------------------------------------------"
echo "  RULE COMPARISON SUMMARY"
echo "  -----------------------------------------------------------------------------"
echo ""
echo "  AWS Security Group:"
echo "    Unique port/protocol combos:  $(wc -l < drift_output/aws_cidrs_aggregated.txt | tr -d ' ')"
echo "    Total rules (AWS count):      ${AWS_TOTAL_RULES} (each CIDR = 1 rule)"
echo ""
echo "  GitHub sg.tf:"
echo "    Unique port/protocol combos:  $(wc -l < drift_output/github_cidrs_aggregated.txt | tr -d ' ')"
echo "    Total rules (AWS count):      ${GITHUB_TOTAL_RULES} (each CIDR = 1 rule)"
echo ""
echo "  Differences:"
echo "    NEW ports in AWS (to add):    ${RULES_TO_ADD}"
echo "    Ports removed from AWS:       ${RULES_REMOVED}"
echo "    Ports with CIDR differences:  ${CIDR_DIFF_COUNT}"
echo "    Structural drift (blocks):    ${STRUCTURAL_DRIFT_COUNT}"
echo "  -----------------------------------------------------------------------------"

# Generate rules_to_add.tf (in drift_output/)
cat > drift_output/rules_to_add.tf << ADDHEADER
# =============================================================================
# RULES TO ADD TO sg.tf
# =============================================================================
# These rules exist in AWS but are NOT in your current sg.tf
# Copy these blocks into your sg.tf file
#
# Generated: $(date)
# Security Group: ${SG_NAME} (${SG_ID})
#
# Total rules to add: ${RULES_TO_ADD}
# =============================================================================

ADDHEADER

if [ "$RULES_TO_ADD" -gt 0 ]; then
    while IFS='|' read -r direction from_port to_port protocol cidrs; do
        desc=$(grep "^${direction}|${from_port}|${to_port}|${protocol}|" drift_output/aws_rules_detail.txt | cut -d'|' -f6 | head -1)
        cat >> drift_output/rules_to_add.tf << RULEBLOCK
  ${direction} {
    from_port   = ${from_port}
    to_port     = ${to_port}
    protocol    = "${protocol}"
    cidr_blocks = [${cidrs}]
    description = "${desc}"
  }

RULEBLOCK
    done < drift_output/rules_to_add_keys.txt
    echo "  [OK] Generated: drift_output/rules_to_add.tf (${RULES_TO_ADD} rules)"
else
    echo "# No new rules to add - sg.tf has all AWS rules" >> drift_output/rules_to_add.tf
    echo "  [OK] Generated: drift_output/rules_to_add.tf (no new rules)"
fi

# Generate rules_removed_from_aws.txt
cat > drift_output/rules_removed_from_aws.txt << REMOVEDHEADER
=============================================================================
RULES IN SG.TF BUT NOT IN AWS
=============================================================================
These rules exist in your sg.tf but are NOT in AWS.
This could mean:
  - Rules were deleted directly in AWS console
  - Rules were never applied (terraform apply not run)
  - Rules were removed by another process

Generated: $(date)
Security Group: ${SG_NAME} (${SG_ID})

Total: ${RULES_REMOVED} rules
=============================================================================

REMOVEDHEADER

if [ "$RULES_REMOVED" -gt 0 ]; then
    while IFS='|' read -r direction from_port to_port protocol cidrs; do
        desc=$(grep "^${direction}|${from_port}|${to_port}|${protocol}|" drift_output/github_rules_detail.txt | cut -d'|' -f6 | head -1)
        echo "${direction}: port ${from_port}-${to_port}/${protocol}" >> drift_output/rules_removed_from_aws.txt
        echo "  CIDRs: ${cidrs}" >> drift_output/rules_removed_from_aws.txt
        echo "  Description: ${desc}" >> drift_output/rules_removed_from_aws.txt
        echo "" >> drift_output/rules_removed_from_aws.txt
    done < drift_output/rules_removed_keys.txt
    echo "  [OK] Generated: drift_output/rules_removed_from_aws.txt (${RULES_REMOVED} rules)"
else
    echo "No rules in sg.tf are missing from AWS." >> drift_output/rules_removed_from_aws.txt
    echo "  [OK] Generated: drift_output/rules_removed_from_aws.txt (none missing)"
fi

# Generate rules_cidr_diff.txt
cat > drift_output/rules_cidr_diff.txt << DIFFHEADER
=============================================================================
RULES WITH CIDR DIFFERENCES
=============================================================================
These rules exist in both AWS and sg.tf but have different CIDR blocks.
You may need to update the CIDRs in sg.tf to match AWS.

Generated: $(date)
Security Group: ${SG_NAME} (${SG_ID})

Total: ${CIDR_DIFF_COUNT} rules with differences
=============================================================================

DIFFHEADER

if [ "$CIDR_DIFF_COUNT" -gt 0 ]; then
    while IFS='|' read -r direction from_port to_port protocol aws_cidrs; do
        key="${direction}|${from_port}|${to_port}|${protocol}"
        github_cidrs=$(grep "^${key}|" drift_output/github_rules.txt | cut -d'|' -f5 | head -1)

        # Compute CIDRs to ADD (in AWS but not in GitHub)
        cidrs_to_add=""
        for cidr in $(echo "$aws_cidrs" | tr ',' '\n'); do
            if ! echo "$github_cidrs" | tr ',' '\n' | grep -qF "$cidr"; then
                if [ -z "$cidrs_to_add" ]; then
                    cidrs_to_add="$cidr"
                else
                    cidrs_to_add="${cidrs_to_add}, ${cidr}"
                fi
            fi
        done

        echo "${direction}: port ${from_port}-${to_port}/${protocol}" >> drift_output/rules_cidr_diff.txt
        echo "  AWS CIDRs:    ${aws_cidrs}" >> drift_output/rules_cidr_diff.txt
        echo "  GitHub CIDRs: ${github_cidrs}" >> drift_output/rules_cidr_diff.txt
        if [ -n "$cidrs_to_add" ]; then
            echo "  ADD these:    ${cidrs_to_add}" >> drift_output/rules_cidr_diff.txt
        fi
        echo "" >> drift_output/rules_cidr_diff.txt
    done < drift_output/cidr_diff_aws.txt
    echo "  [OK] Generated: drift_output/rules_cidr_diff.txt (${CIDR_DIFF_COUNT} differences)"
else
    echo "No CIDR differences found." >> drift_output/rules_cidr_diff.txt
    echo "  [OK] Generated: drift_output/rules_cidr_diff.txt (no differences)"
fi

# -----------------------------------------------------------------------------
# GENERATE all_changes.txt - CONSOLIDATED VIEW (in drift_output/)
# -----------------------------------------------------------------------------
cat > drift_output/all_changes.txt << ALLCHANGESHEADER
=============================================================================
ALL CHANGES NEEDED TO SYNC sg.tf WITH AWS
=============================================================================
This file consolidates ALL differences between AWS and GitHub sg.tf

Generated: $(date)
Security Group: ${SG_NAME} (${SG_ID})

SUMMARY:
  - New rules to add:        ${RULES_TO_ADD}
  - Rules removed from AWS:  ${RULES_REMOVED}
  - Rules with CIDR changes: ${CIDR_DIFF_COUNT}

=============================================================================

ALLCHANGESHEADER

# Section 1: New rules (complete rule blocks to add)
if [ "$RULES_TO_ADD" -gt 0 ]; then
    cat >> drift_output/all_changes.txt << 'NEWSECTION'
-----------------------------------------------------------------------------
SECTION 1: NEW RULES TO ADD
-----------------------------------------------------------------------------
Copy these complete rule blocks into your sg.tf:

NEWSECTION
    while IFS='|' read -r direction from_port to_port protocol cidrs; do
        desc=$(grep "^${direction}|${from_port}|${to_port}|${protocol}|" drift_output/aws_rules_detail.txt | cut -d'|' -f6 | head -1)
        cat >> drift_output/all_changes.txt << NEWRULE
  ${direction} {
    from_port   = ${from_port}
    to_port     = ${to_port}
    protocol    = "${protocol}"
    cidr_blocks = [${cidrs}]
    description = "${desc}"
  }

NEWRULE
    done < drift_output/rules_to_add_keys.txt
fi

# Section 2: CIDR changes (update existing rules)
if [ "$CIDR_DIFF_COUNT" -gt 0 ]; then
    cat >> drift_output/all_changes.txt << 'CIDRSECTION'
-----------------------------------------------------------------------------
SECTION 2: CIDR CHANGES FOR EXISTING RULES
-----------------------------------------------------------------------------
Update these existing rules in sg.tf - add the missing CIDRs:
(CIDRs aggregated across all rule blocks for each port)

CIDRSECTION
    while IFS='|' read -r direction from_port to_port protocol aws_cidrs; do
        key="${direction}|${from_port}|${to_port}|${protocol}"
        # Use AGGREGATED GitHub CIDRs (combines all rule blocks for this port)
        github_cidrs=$(grep "^${key}|" drift_output/github_cidrs_aggregated.txt | cut -d'|' -f5 | head -1)
        
        # Compute CIDRs to ADD (in AWS but not in GitHub)
        cidrs_to_add=""
        for cidr in $(echo "$aws_cidrs" | tr ',' '\n'); do
            if ! echo "$github_cidrs" | tr ',' '\n' | grep -qF "$cidr"; then
                if [ -z "$cidrs_to_add" ]; then
                    cidrs_to_add="$cidr"
                else
                    cidrs_to_add="${cidrs_to_add}, ${cidr}"
                fi
            fi
        done
        
        # Compute CIDRs to REMOVE (in GitHub but not in AWS)
        cidrs_to_remove=""
        for cidr in $(echo "$github_cidrs" | tr ',' '\n'); do
            if ! echo "$aws_cidrs" | tr ',' '\n' | grep -qF "$cidr"; then
                if [ -z "$cidrs_to_remove" ]; then
                    cidrs_to_remove="$cidr"
                else
                    cidrs_to_remove="${cidrs_to_remove}, ${cidr}"
                fi
            fi
        done
        
        echo "${direction}: port ${from_port}-${to_port}/${protocol}" >> drift_output/all_changes.txt
        echo "  GitHub sg.tf (all blocks): [${github_cidrs}]" >> drift_output/all_changes.txt
        echo "  AWS current (all sources): [${aws_cidrs}]" >> drift_output/all_changes.txt
        if [ -n "$cidrs_to_add" ]; then
            echo "  CIDRs to ADD to sg.tf:     ${cidrs_to_add}" >> drift_output/all_changes.txt
        fi
        if [ -n "$cidrs_to_remove" ]; then
            echo "  CIDRs to REMOVE from sg.tf: ${cidrs_to_remove}" >> drift_output/all_changes.txt
        fi
        echo "" >> drift_output/all_changes.txt
    done < drift_output/cidr_diff_aws.txt
fi

# Section 3: Removed rules (informational)
if [ "$RULES_REMOVED" -gt 0 ]; then
    cat >> drift_output/all_changes.txt << 'REMOVEDSECTION'
-----------------------------------------------------------------------------
SECTION 3: RULES IN SG.TF BUT NOT IN AWS (Review needed)
-----------------------------------------------------------------------------
These rules exist in sg.tf but not in AWS. Either:
  - Remove them from sg.tf, OR
  - They need to be re-added to AWS

REMOVEDSECTION
    while IFS='|' read -r direction from_port to_port protocol cidrs; do
        echo "${direction}: port ${from_port}-${to_port}/${protocol} [${cidrs}]" >> drift_output/all_changes.txt
    done < drift_output/rules_removed_keys.txt
    echo "" >> drift_output/all_changes.txt
fi

# If no changes needed (check structural drift too)
if [ "$RULES_TO_ADD" -eq 0 ] && [ "$RULES_REMOVED" -eq 0 ] && [ "$CIDR_DIFF_COUNT" -eq 0 ] && [ "$STRUCTURAL_DRIFT_COUNT" -eq 0 ]; then
    echo "NO CHANGES NEEDED - sg.tf matches AWS state!" >> drift_output/all_changes.txt
elif [ "$RULES_TO_ADD" -eq 0 ] && [ "$RULES_REMOVED" -eq 0 ] && [ "$CIDR_DIFF_COUNT" -eq 0 ] && [ "$STRUCTURAL_DRIFT_COUNT" -gt 0 ]; then
    cat >> drift_output/all_changes.txt << 'STRUCTSECTION'
-----------------------------------------------------------------------------
STRUCTURAL DRIFT DETECTED
-----------------------------------------------------------------------------
CIDRs match but rule blocks are organized differently.
AWS has multiple rule blocks with different descriptions for the same port,
but sg.tf combines them into fewer blocks.

Terraform WILL show changes even though the same IPs are allowed!

RECOMMENDED: Replace sg.tf content with sg_generated.tf to match AWS structure.
See drift_output/structural_drift.txt for details.

STRUCTSECTION
fi

# Add reminder to check tags
cat >> drift_output/all_changes.txt << 'TAGREMINDER'
=============================================================================
REMINDER: CHECK TAGS
=============================================================================
This script compares RULES only. Don't forget to verify that the security
group TAGS in sg.tf match what's in AWS. Check:
  - Name tag
  - Environment tag
  - Any other required tags

=============================================================================
TAGREMINDER

echo "  [OK] Generated: drift_output/all_changes.txt (consolidated view)"

# -----------------------------------------------------------------------------
# GENERATE description_diff.txt - DESCRIPTION COMPARISON
# -----------------------------------------------------------------------------
echo "  Comparing rule descriptions..."

cat > drift_output/description_diff.txt << DESCHEADER
=============================================================================
RULES WITH DESCRIPTION DIFFERENCES
=============================================================================
These rules exist in both AWS and sg.tf but have different descriptions.

Generated: $(date)
Security Group: ${SG_NAME} (${SG_ID})
=============================================================================

DESCHEADER

DESC_DIFF_COUNT=0

# Compare descriptions for matching rules
while IFS='|' read -r direction from_port to_port protocol cidrs aws_desc; do
    key="${direction}|${from_port}|${to_port}|${protocol}"
    
    # Get GitHub description for same rule
    github_desc=$(grep "^${key}|" drift_output/github_rules_detail.txt | cut -d'|' -f6 | head -1)
    
    # Compare descriptions (if rule exists in both)
    if grep -q "^${key}|" drift_output/github_rules.txt 2>/dev/null; then
        if [ "$aws_desc" != "$github_desc" ]; then
            DESC_DIFF_COUNT=$((DESC_DIFF_COUNT + 1))
            echo "${direction}: port ${from_port}-${to_port}/${protocol}" >> drift_output/description_diff.txt
            echo "  AWS Description:    \"${aws_desc}\"" >> drift_output/description_diff.txt
            echo "  GitHub Description: \"${github_desc}\"" >> drift_output/description_diff.txt
            echo "" >> drift_output/description_diff.txt
        fi
    fi
done < drift_output/aws_rules_detail.txt

if [ "$DESC_DIFF_COUNT" -eq 0 ]; then
    echo "No description differences found." >> drift_output/description_diff.txt
fi

# Add count to header
sed -i "s/=============================================================================$/Total: ${DESC_DIFF_COUNT} rules with description differences\n=============================================================================/" drift_output/description_diff.txt 2>/dev/null || true

echo "  [OK] Generated: drift_output/description_diff.txt (${DESC_DIFF_COUNT} differences)"

# -----------------------------------------------------------------------------
# GENERATE drift_summary.json - JSON OUTPUT FOR AUTOMATION
# -----------------------------------------------------------------------------
cat > drift_output/drift_summary.json << JSONEOF
{
  "generated": "$(date -Iseconds 2>/dev/null || date)",
  "script_version": "${SCRIPT_VERSION}",
  "security_group": {
    "id": "${SG_ID}",
    "name": "${SG_NAME}",
    "vpc_id": "${SG_VPC}",
    "description": "${SG_DESC}"
  },
  "summary": {
    "drift_detected": $([ "$RULES_TO_ADD" -gt 0 ] || [ "$RULES_REMOVED" -gt 0 ] || [ "$CIDR_DIFF_COUNT" -gt 0 ] || [ "$STRUCTURAL_DRIFT_COUNT" -gt 0 ] && echo "true" || echo "false"),
    "aws_rule_count": ${AWS_RULE_COUNT},
    "github_rule_count": ${GITHUB_RULE_COUNT},
    "rules_to_add": ${RULES_TO_ADD},
    "rules_removed": ${RULES_REMOVED},
    "cidr_differences": ${CIDR_DIFF_COUNT},
    "structural_drift": ${STRUCTURAL_DRIFT_COUNT},
    "description_differences": ${DESC_DIFF_COUNT}
  },
  "ip_translation": {
    "matched": ${MATCH_COUNT},
    "unmatched": ${UNMATCH_COUNT}
  }
}
JSONEOF

echo "  [OK] Generated: drift_output/drift_summary.json"

# -----------------------------------------------------------------------------
# GENERATE pr_summary.md - PR-READY MARKDOWN SUMMARY
# -----------------------------------------------------------------------------
cat > drift_output/pr_summary.md << PRHEADER
# Security Group Drift Analysis

## Summary

| Metric | Value |
|--------|-------|
| Security Group | \`${SG_NAME}\` (${SG_ID}) |
| VPC | \`${SG_VPC}\` |
| Generated | $(date) |
| Script Version | v${SCRIPT_VERSION} |

## Drift Status

PRHEADER

if [ "$RULES_TO_ADD" -gt 0 ] || [ "$RULES_REMOVED" -gt 0 ] || [ "$CIDR_DIFF_COUNT" -gt 0 ] || [ "$STRUCTURAL_DRIFT_COUNT" -gt 0 ]; then
    if [ "$STRUCTURAL_DRIFT_COUNT" -gt 0 ] && [ "$RULES_TO_ADD" -eq 0 ] && [ "$RULES_REMOVED" -eq 0 ] && [ "$CIDR_DIFF_COUNT" -eq 0 ]; then
        echo "**[WARNING] STRUCTURAL DRIFT - Use sg_generated.tf**" >> drift_output/pr_summary.md
    else
        echo "**[WARNING] DRIFT DETECTED**" >> drift_output/pr_summary.md
    fi
else
    echo "**[OK] NO DRIFT - AWS matches GitHub**" >> drift_output/pr_summary.md
fi

cat >> drift_output/pr_summary.md << PRTABLE

## Changes Required

| Change Type | Count |
|-------------|-------|
| New rules to add | ${RULES_TO_ADD} |
| Rules removed from AWS | ${RULES_REMOVED} |
| CIDR differences | ${CIDR_DIFF_COUNT} |
| Structural drift | ${STRUCTURAL_DRIFT_COUNT} |
| Description differences | ${DESC_DIFF_COUNT} |

## IP Translation

| Status | Count |
|--------|-------|
| Matched (local.ipX) | ${MATCH_COUNT} |
| Unmatched (raw IP) | ${UNMATCH_COUNT} |

PRTABLE

# Add new rules section if any
if [ "$RULES_TO_ADD" -gt 0 ]; then
    cat >> drift_output/pr_summary.md << 'PRNEWRULES'
## New Rules to Add

The following rules exist in AWS but not in `sg.tf`:

```hcl
PRNEWRULES
    while IFS='|' read -r direction from_port to_port protocol cidrs; do
        desc=$(grep "^${direction}|${from_port}|${to_port}|${protocol}|" drift_output/aws_rules_detail.txt | cut -d'|' -f6 | head -1)
        cat >> drift_output/pr_summary.md << PRRULE
  ${direction} {
    from_port   = ${from_port}
    to_port     = ${to_port}
    protocol    = "${protocol}"
    cidr_blocks = [${cidrs}]
    description = "${desc}"
  }
PRRULE
    done < drift_output/rules_to_add_keys.txt
    echo '```' >> drift_output/pr_summary.md
    echo "" >> drift_output/pr_summary.md
fi

# Add CIDR diff section if any
if [ "$CIDR_DIFF_COUNT" -gt 0 ]; then
    cat >> drift_output/pr_summary.md << 'PRCIDRHDR'
## CIDR Differences

The following rules have different CIDRs between AWS and GitHub:

| Rule | CIDRs to Add |
|------|--------------|
PRCIDRHDR
    while IFS='|' read -r direction from_port to_port protocol aws_cidrs; do
        key="${direction}|${from_port}|${to_port}|${protocol}"
        github_cidrs=$(grep "^${key}|" drift_output/github_rules.txt | cut -d'|' -f5 | head -1)
        
        cidrs_to_add=""
        for cidr in $(echo "$aws_cidrs" | tr ',' '\n'); do
            if ! echo "$github_cidrs" | tr ',' '\n' | grep -qF "$cidr"; then
                if [ -z "$cidrs_to_add" ]; then
                    cidrs_to_add="$cidr"
                else
                    cidrs_to_add="${cidrs_to_add}, ${cidr}"
                fi
            fi
        done
        
        echo "| ${direction} ${from_port}-${to_port}/${protocol} | \`${cidrs_to_add}\` |" >> drift_output/pr_summary.md
    done < drift_output/cidr_diff_aws.txt
    echo "" >> drift_output/pr_summary.md
fi

cat >> drift_output/pr_summary.md << 'PRFOOTER'
---

*Generated by drift_check.sh - READ ONLY (no changes made to AWS)*
PRFOOTER

echo "  [OK] Generated: drift_output/pr_summary.md"

# Determine overall drift status (include structural drift)
if [ "$RULES_TO_ADD" -eq 0 ] && [ "$RULES_REMOVED" -eq 0 ] && [ "$CIDR_DIFF_COUNT" -eq 0 ] && [ "$STRUCTURAL_DRIFT_COUNT" -eq 0 ]; then
    DRIFT_FOUND=false
    DRIFT_STATUS="NO DRIFT - AWS matches GitHub sg.tf"
else
    DRIFT_FOUND=true
    if [ "$STRUCTURAL_DRIFT_COUNT" -gt 0 ] && [ "$RULES_TO_ADD" -eq 0 ] && [ "$RULES_REMOVED" -eq 0 ] && [ "$CIDR_DIFF_COUNT" -eq 0 ]; then
        DRIFT_STATUS="STRUCTURAL DRIFT - Same CIDRs but different rule organization"
    else
        DRIFT_STATUS="DRIFT DETECTED"
    fi
fi

# Create the final sg_generated.tf with detailed header
cat > drift_output/sg_generated.tf << HEADEREOF
# =============================================================================
# SG_GENERATED.TF - Current AWS Security Group State
# =============================================================================
# This file shows the COMPLETE current state of the security group in AWS,
# translated to use local.ipX references.
#
# SCRIPT INFO:
#   Generated by: drift_check.sh v${SCRIPT_VERSION}
#   Generated on: $(date)
#   Server: $(hostname)
#
# SECURITY GROUP:
#   ID:   ${SG_ID}
#   Name: ${SG_NAME}
#   VPC:  ${SG_VPC}
#
# =============================================================================
#                           CHANGE SUMMARY
# =============================================================================
#
# DRIFT STATUS: ${DRIFT_STATUS}
#
# RULES TO ADD (in AWS, not in sg.tf):     ${RULES_TO_ADD}
# RULES REMOVED (in sg.tf, not in AWS):    ${RULES_REMOVED}
# RULES WITH CIDR DIFFERENCES:             ${CIDR_DIFF_COUNT}
# STRUCTURAL DRIFT (rule grouping):        ${STRUCTURAL_DRIFT_COUNT}
#
# IP TRANSLATION:
#   Matched IPs -> local.ipX:  ${MATCH_COUNT}
#   Unmatched (raw IPs):       ${UNMATCH_COUNT}
#
# =============================================================================
#                         WHAT TO DO NEXT
# =============================================================================
HEADEREOF

if [ "$DRIFT_FOUND" = true ]; then
    cat >> drift_output/sg_generated.tf << NEXTEOF
#
# 1. REVIEW: rules_to_add.tf
#    -> Copy these rule blocks into your sg.tf
#
# 2. REVIEW: drift_output/rules_removed_from_aws.txt
#    -> Decide if these should be re-added to AWS or removed from sg.tf
#
# 3. REVIEW: drift_output/rules_cidr_diff.txt
#    -> Update CIDRs in sg.tf to match AWS state
#
# 4. COMMIT: Create a new branch with your changes
#
# 5. VERIFY: Run 'terraform plan' - should show no changes if synced
#
NEXTEOF
else
    cat >> drift_output/sg_generated.tf << SYNCEOF
#
# Your sg.tf is IN SYNC with AWS!
# No changes needed.
#
SYNCEOF
fi

# Add new rules summary to header if any
if [ "$RULES_TO_ADD" -gt 0 ]; then
    cat >> drift_output/sg_generated.tf << NEWRULESEOF
# =============================================================================
#                    NEW RULES IN AWS (add to sg.tf)
# =============================================================================
NEWRULESEOF
    while IFS='|' read -r direction from_port to_port protocol cidrs; do
        echo "#   ${direction}: ${from_port}-${to_port}/${protocol} [${cidrs}]" >> drift_output/sg_generated.tf
    done < drift_output/rules_to_add_keys.txt
    echo "#" >> drift_output/sg_generated.tf
fi

# Add removed rules summary if any
if [ "$RULES_REMOVED" -gt 0 ]; then
    cat >> drift_output/sg_generated.tf << REMOVEDRULESEOF
# =============================================================================
#               RULES IN SG.TF BUT NOT IN AWS (verify)
# =============================================================================
REMOVEDRULESEOF
    while IFS='|' read -r direction from_port to_port protocol cidrs; do
        echo "#   ${direction}: ${from_port}-${to_port}/${protocol}" >> drift_output/sg_generated.tf
    done < drift_output/rules_removed_keys.txt
    echo "#" >> drift_output/sg_generated.tf
fi

# Add CIDR diff summary if any
if [ "$CIDR_DIFF_COUNT" -gt 0 ]; then
    cat >> drift_output/sg_generated.tf << CIDRDIFFEOF
# =============================================================================
#                    CIDR DIFFERENCES (update sg.tf)
# =============================================================================
CIDRDIFFEOF
    while IFS='|' read -r direction from_port to_port protocol aws_cidrs; do
        echo "#   ${direction}: ${from_port}-${to_port}/${protocol} - CIDRs differ" >> drift_output/sg_generated.tf
    done < drift_output/cidr_diff_aws.txt
    echo "#" >> drift_output/sg_generated.tf
fi

# Add unmatched IPs warning if any
if [ "$UNMATCH_COUNT" -gt 0 ]; then
    cat >> drift_output/sg_generated.tf << UNMATCHEOF
# =============================================================================
#                WARNING: UNMATCHED IPs (need data.tf update)
# =============================================================================
# The following IPs from AWS could not be matched to local.ipX:
UNMATCHEOF
    cat drift_output/unmatched_ips.txt | while read -r ip; do
        echo "#   - ${ip}" >> drift_output/sg_generated.tf
    done
    cat >> drift_output/sg_generated.tf << UNMATCHEOF2
#
# These IPs appear as raw values in this file. You should:
#   1. Add them to your Secrets Manager secret
#   2. Add corresponding local.ipX entries in data.tf
#   3. Re-run this script
#
UNMATCHEOF2
fi

echo "# =============================================================================" >> drift_output/sg_generated.tf
echo "" >> drift_output/sg_generated.tf

# Append the terraform code body
cat drift_output/sg_temp_body.tf >> drift_output/sg_generated.tf

echo "  [OK] Generated: drift_output/sg_generated.tf"

# Create drift report file
cat > drift_output/drift_report.txt << REPORTHEADER
=============================================================================
DRIFT REPORT - AWS vs GitHub
=============================================================================
Generated: $(date)
Security Group ID: ${SG_ID}
Security Group Name: ${SG_NAME}
Script Version: ${SCRIPT_VERSION}

=============================================================================
SUMMARY
=============================================================================

AWS Rules:     ${AWS_RULE_COUNT}
GitHub Rules:  ${GITHUB_RULE_COUNT}

Rules to Add:       ${RULES_TO_ADD}
Rules Removed:      ${RULES_REMOVED}
CIDR Differences:   ${CIDR_DIFF_COUNT}
Description Diffs:  ${DESC_DIFF_COUNT}

Drift Status: ${DRIFT_STATUS}

=============================================================================
FILES GENERATED
=============================================================================

drift_output/ (ALL output - keeps repo clean):
  all_changes.txt         - CONSOLIDATED view of ALL changes
  rules_to_add.tf         - NEW rules to copy into sg.tf
  sg_generated.tf         - Complete AWS state (use as reference)
  rules_removed_from_aws.txt - Rules in sg.tf but not in AWS
  rules_cidr_diff.txt     - Rules with different CIDRs
  description_diff.txt    - Rules with different descriptions
  drift_summary.json      - JSON output for automation
  pr_summary.md           - PR-ready summary in markdown
  ip_to_local_map.txt     - IP to local mapping reference

REPORTHEADER

echo "  [OK] Generated: drift_output/drift_report.txt"

# Show summary on screen
echo ""
echo "-----------------------------------------------------------------------------"
if [ "$DRIFT_FOUND" = true ]; then
    echo "DRIFT DETECTED:"
    [ "$RULES_TO_ADD" -gt 0 ] && echo "  - ${RULES_TO_ADD} rules in AWS need to be added to sg.tf"
    [ "$RULES_REMOVED" -gt 0 ] && echo "  - ${RULES_REMOVED} rules in sg.tf are not in AWS"
    [ "$CIDR_DIFF_COUNT" -gt 0 ] && echo "  - ${CIDR_DIFF_COUNT} rules have different CIDRs"
    [ "$STRUCTURAL_DRIFT_COUNT" -gt 0 ] && echo "  - ${STRUCTURAL_DRIFT_COUNT} ports have structural differences (description grouping)"
    [ "$DESC_DIFF_COUNT" -gt 0 ] && echo "  - ${DESC_DIFF_COUNT} rules have different descriptions"
    echo ""
    echo "  >>> RECOMMENDED: Use sg_generated.tf as your source of truth <<<"
else
    echo "NO DRIFT - AWS and sg.tf are in sync!"
fi
echo "-----------------------------------------------------------------------------"

# -----------------------------------------------------------------------------
# FINAL SUMMARY
# -----------------------------------------------------------------------------
echo ""
echo "[7/7] Complete"
echo ""
echo "============================================================================="
echo "   SUMMARY"
echo "============================================================================="
echo ""
echo "SECURITY GROUP:"
echo "  ID:      ${SG_ID}"
echo "  Name:    ${SG_NAME}"
echo "  VPC:     ${SG_VPC}"
echo ""
echo "RULES ANALYSIS:"
echo "  AWS rules:              ${AWS_RULE_COUNT}"
echo "  GitHub sg.tf rules:     ${GITHUB_RULE_COUNT}"
echo "  Rules to ADD:           ${RULES_TO_ADD}"
echo "  Rules REMOVED from AWS: ${RULES_REMOVED}"
echo "  CIDR differences:       ${CIDR_DIFF_COUNT}"
echo "  Structural drift:       ${STRUCTURAL_DRIFT_COUNT}"
echo "  Description differences: ${DESC_DIFF_COUNT}"
echo ""
echo "IP TRANSLATION:"
echo "  Matched:   ${MATCH_COUNT} IPs -> local.ipX"
echo "  Unmatched: ${UNMATCH_COUNT} IPs (shown as raw)"
echo ""
if [ "$DRIFT_FOUND" = true ]; then
    echo "DRIFT STATUS: ${DRIFT_STATUS}"
    echo ""
    echo "NEXT STEPS:"
    echo "  1. ** REVIEW: drift_output/sg_generated.tf - COMPLETE AWS state **"
    echo "     This file shows EXACTLY how AWS is configured."
    echo "     For full sync, copy this content to your sg.tf"
    echo ""
    echo "  2. Review drift_output/all_changes.txt - consolidated view of all changes"
    if [ "$STRUCTURAL_DRIFT_COUNT" -gt 0 ]; then
        echo "  3. Review drift_output/structural_drift.txt - different rule groupings"
    fi
    echo "  4. Review drift_output/rules_cidr_diff.txt - update CIDRs as needed"
    echo "  5. Review drift_output/pr_summary.md for PR template"
    echo "  6. Create new branch, commit changes"
    echo "  7. Run terraform plan (should show no changes)"
else
    echo "DRIFT STATUS: IN SYNC (no drift detected)"
fi
echo ""
if [ "$UNMATCH_COUNT" -gt 0 ]; then
    echo "WARNING: ${UNMATCH_COUNT} IPs could not be matched to data.tf locals"
    echo "         Review drift_output/unmatched_ips.txt - may need to update secrets/data.tf"
    echo ""
fi
echo "============================================================================="
echo "FILES GENERATED (all in drift_output/ - repo stays clean):"
echo "============================================================================="
echo "  ** sg_generated.tf **     - COMPLETE AWS state - USE THIS FOR FULL SYNC"
echo "  all_changes.txt           - CONSOLIDATED view of ALL changes needed"
echo "  rules_to_add.tf           - NEW rules to copy into sg.tf"
echo "  structural_drift.txt      - Ports with different rule groupings"
echo "  rules_removed_from_aws.txt - Rules in sg.tf but not in AWS"
echo "  rules_cidr_diff.txt       - Rules with different CIDRs"
echo "  description_diff.txt      - Rules with different descriptions"
echo "  drift_summary.json        - JSON output for automation"
echo "  pr_summary.md             - PR-ready summary in markdown"
echo "  drift_report.txt          - Full analysis report"
echo "  ip_to_local_map.txt       - IP to local mapping reference"
echo "============================================================================="
echo ""
echo "*** NO CHANGES WERE MADE TO AWS - This was READ ONLY ***"
echo ""

# -----------------------------------------------------------------------------
# CLEANUP PROMPT
# -----------------------------------------------------------------------------
read -p "Clean up temporary files? (y/n): " cleanup
if [ "$cleanup" == "y" ]; then
    rm -f aws_sg.json aws_sg_detail.json secret_values.json
    rm -f drift_output/matched_ips.txt drift_output/matched_ips_masked.txt drift_output/unmatched_ips.txt drift_output/sg_temp_body.tf
    rm -f drift_output/github_rules.txt drift_output/github_rules_detail.txt
    rm -f drift_output/aws_rules.txt drift_output/aws_rules_detail.txt
    rm -f drift_output/rules_to_add_keys.txt drift_output/rules_removed_keys.txt
    rm -f drift_output/cidr_diff_aws.txt drift_output/cidr_diff_github.txt
    echo "Cleaned up temporary files"
else
    echo ""
    echo "============================================================================="
    echo "TEMPORARY FILES (kept in drift_output/):"
    echo "============================================================================="
    echo "  aws_sg.json             - Raw AWS API response for security group"
    echo "  aws_sg_detail.json      - Parsed security group details"
    echo "  secret_values.json      - Secret values (CONTAINS ACTUAL IPs - sensitive)"
    echo ""
    echo "  drift_output/matched_ips.txt        - IPs translated (CONTAINS IPs - sensitive)"
    echo "  drift_output/matched_ips_masked.txt - IPs translated (SAFE TO SHARE)"
    echo "  drift_output/unmatched_ips.txt   - IPs that could not be matched"
    echo "  drift_output/sg_temp_body.tf     - Intermediate terraform body (pre-header)"
    echo "  drift_output/github_rules.txt    - Parsed rules from sg.tf"
    echo "  drift_output/github_rules_detail.txt - Detailed rule info from sg.tf"
    echo "  drift_output/aws_rules.txt       - Parsed rules from AWS"
    echo "  drift_output/aws_rules_detail.txt - Detailed rule info from AWS"
    echo "  drift_output/rules_to_add_keys.txt - Rule keys to add (working file)"
    echo "  drift_output/rules_removed_keys.txt - Rule keys removed (working file)"
    echo "  drift_output/cidr_diff_aws.txt   - CIDR differences from AWS side"
    echo "  drift_output/cidr_diff_github.txt - CIDR differences from GitHub side"
    echo "============================================================================="
    echo ""
    echo "NOTE: secret_values.json contains actual IP addresses - delete when done!"
fi

# -----------------------------------------------------------------------------
# DEBUG MODE OUTPUT
# -----------------------------------------------------------------------------
if [ "$DEBUG_MODE" = true ]; then
    echo ""
    echo "============================================================================="
    echo "   DEBUG DIAGNOSTICS"
    echo "============================================================================="
    echo ""
    echo "=== RULE COUNTS ==="
    echo "AWS rules:    $(wc -l < drift_output/aws_rules.txt 2>/dev/null || echo 0)"
    echo "GitHub rules: $(wc -l < drift_output/github_rules.txt 2>/dev/null || echo 0)"
    echo ""
    echo "=== IP TRANSLATION ==="
    echo "Matched:   $(wc -l < drift_output/matched_ips.txt 2>/dev/null || echo 0)"
    echo "Unmatched: $(wc -l < drift_output/unmatched_ips.txt 2>/dev/null || echo 0)"
    echo ""
    echo "=== COMPARISON FLAGS ==="
    echo "Rules to add:     $(wc -l < drift_output/rules_to_add_keys.txt 2>/dev/null || echo 0)"
    echo "Rules removed:    $(wc -l < drift_output/rules_removed_keys.txt 2>/dev/null || echo 0)"
    echo "CIDR diff (AWS):  $(wc -l < drift_output/cidr_diff_aws.txt 2>/dev/null || echo 0)"
    echo "CIDR diff (GH):   $(wc -l < drift_output/cidr_diff_github.txt 2>/dev/null || echo 0)"
    echo ""
    echo "=== SAMPLE AWS RULE (line 1) ==="
    head -1 drift_output/aws_rules.txt 2>/dev/null || echo "(none)"
    echo ""
    echo "=== SAMPLE GITHUB RULE (line 1) ==="
    head -1 drift_output/github_rules.txt 2>/dev/null || echo "(none)"
    echo ""
    echo "=== AWS RULES (numbered, first 20) ==="
    nl -ba drift_output/aws_rules.txt 2>/dev/null | head -20 || echo "(none)"
    echo ""
    echo "=== GITHUB RULES (numbered, first 20) ==="
    nl -ba drift_output/github_rules.txt 2>/dev/null | head -20 || echo "(none)"
    echo ""
    echo "=== UNMATCHED IPs (first 10) ==="
    head -10 drift_output/unmatched_ips.txt 2>/dev/null || echo "(none)"
    echo ""
    echo "=== RULES FLAGGED TO ADD ==="
    cat drift_output/rules_to_add_keys.txt 2>/dev/null || echo "(none)"
    echo ""
    echo "=== RULES FLAGGED AS REMOVED ==="
    cat drift_output/rules_removed_keys.txt 2>/dev/null || echo "(none)"
    echo ""
    echo "=== CIDR DIFFERENCES (AWS side) ==="
    cat drift_output/cidr_diff_aws.txt 2>/dev/null || echo "(none)"
    echo ""
    echo "============================================================================="
    echo "   END DEBUG OUTPUT"
    echo "============================================================================="
fi

echo ""
echo "============================================================================="
echo "   DONE"
echo "============================================================================="
echo ""