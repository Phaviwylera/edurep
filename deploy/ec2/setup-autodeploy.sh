#!/usr/bin/env bash
# ONE-TIME AWS setup for push-triggered deploys (GitHub Actions -> SSM).
#
# Run this from YOUR LAPTOP (not the EC2 instance), with AWS CLI and gh CLI
# logged in:
#
#   EC2_INSTANCE_ID=i-0abc... bash deploy/ec2/setup-autodeploy.sh
#
# It creates, idempotently:
#   * the GitHub Actions OIDC provider in your AWS account
#   * a least-privilege role GitHub can assume only from main of this repo
#   * an EC2 instance profile with AmazonSSMManagedInstanceCore, attached to
#     your instance, so `aws ssm send-command` works with NO inbound SSH
#   * the three GitHub repository variables the workflow needs
#
# Requires IAM permissions to manage roles/instance profiles and
# ec2:AssociateIamInstanceProfile. Safe to re-run.
set -euo pipefail

command -v aws >/dev/null 2>&1 || { echo "ERROR: AWS CLI not installed" >&2; exit 1; }

REGION="${AWS_REGION:-us-east-1}"
REPO="${GITHUB_REPO:-Phaviwylera/edurep}"
BRANCH="${DEPLOY_BRANCH:-main}"
INSTANCE_ID="${EC2_INSTANCE_ID:?ERROR: set EC2_INSTANCE_ID=i-0abc... }"
ROLE_NAME="${ROLE_NAME:-btc-hunt-gha-deploy}"
PROFILE_NAME="${INSTANCE_PROFILE_NAME:-btc-hunt-ssm-profile}"
SSM_ROLE_NAME="${SSM_ROLE_NAME:-btc-hunt-ssm-role}"
OIDC_HOST="token.actions.githubusercontent.com"
OIDC_CLIENT="sts.amazonaws.com"
THUMBPRINT="6938fd4d98bab03faadb97b34396831e3780aea1"

export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
OIDC_ARN="arn:aws:iam::$ACCOUNT_ID:oidc-provider/$OIDC_HOST"
echo "[setup] account $ACCOUNT_ID / region $REGION / repo $REPO@$BRANCH / instance $INSTANCE_ID"

# 1. GitHub OIDC identity provider (one per AWS account) ---------------------
if aws iam get-open-id-connect-provider \
     --open-id-connect-provider-arn "$OIDC_ARN" >/dev/null 2>&1; then
  echo "[setup] OIDC provider already exists"
else
  aws iam create-open-id-connect-provider \
    --url "https://$OIDC_HOST" \
    --client-id-list "$OIDC_CLIENT" \
    --thumbprint-list "$THUMBPRINT" >/dev/null
  echo "[setup] created OIDC provider"
fi

# 2. Role GitHub Actions assumes, scoped to this repo + branch ---------------
TRUST="$(mktemp)"
cat > "$TRUST" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "$OIDC_ARN"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "$OIDC_CLIENT",
        "token.actions.githubusercontent.com:sub": "repo:$REPO:ref:refs/heads/$BRANCH"
      }
    }
  }]
}
EOF

if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  aws iam update-assume-role-policy --role-name "$ROLE_NAME" \
    --policy-document "file://$TRUST" >/dev/null
  echo "[setup] updated trust policy on $ROLE_NAME"
else
  aws iam create-role --role-name "$ROLE_NAME" \
    --assume-role-policy-document "file://$TRUST" >/dev/null
  echo "[setup] created role $ROLE_NAME"
fi

POLICY="$(mktemp)"
cat > "$POLICY" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ssm:SendCommand"],
      "Resource": [
        "arn:aws:ssm:$REGION::document/AWS-RunShellScript",
        "arn:aws:ec2:$REGION:$ACCOUNT_ID:instance/$INSTANCE_ID"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations"],
      "Resource": "*"
    }
  ]
}
EOF
aws iam put-role-policy --role-name "$ROLE_NAME" \
  --policy-name "btc-hunt-ssm-deploy" \
  --policy-document "file://$POLICY" >/dev/null
rm -f "$TRUST" "$POLICY"

# 3. Instance profile so the SSM agent on EC2 can receive commands -----------
EC2_TRUST="$(mktemp)"
cat > "$EC2_TRUST" <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}
EOF
if ! aws iam get-role --role-name "$SSM_ROLE_NAME" >/dev/null 2>&1; then
  aws iam create-role --role-name "$SSM_ROLE_NAME" \
    --assume-role-policy-document "file://$EC2_TRUST" >/dev/null
fi
rm -f "$EC2_TRUST"
aws iam attach-role-policy --role-name "$SSM_ROLE_NAME" \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore

if ! aws iam get-instance-profile \
       --instance-profile-name "$PROFILE_NAME" >/dev/null 2>&1; then
  aws iam create-instance-profile \
    --instance-profile-name "$PROFILE_NAME" >/dev/null
fi

if ! aws iam get-instance-profile --instance-profile-name "$PROFILE_NAME" \
       --query "InstanceProfile.Roles[?RoleName=='$SSM_ROLE_NAME'].RoleName" \
       --output text | grep -q .; then
  # IAM is eventually consistent: retry briefly after creating the profile.
  for _ in $(seq 1 10); do
    if aws iam add-role-to-instance-profile \
         --instance-profile-name "$PROFILE_NAME" \
         --role-name "$SSM_ROLE_NAME" >/dev/null 2>&1; then break; fi
    sleep 3
  done
fi

CURRENT_PROFILE="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].IamInstanceProfile.Arn' --output text)"
if [ "$CURRENT_PROFILE" = "None" ] || [ -z "$CURRENT_PROFILE" ]; then
  aws ec2 associate-iam-instance-profile --instance-id "$INSTANCE_ID" \
    --iam-instance-profile "Name=$PROFILE_NAME" >/dev/null
  echo "[setup] attached $PROFILE_NAME to $INSTANCE_ID"
else
  echo "[setup] instance already has a profile: $CURRENT_PROFILE"
  echo "         make sure it includes AmazonSSMManagedInstanceCore"
fi

ROLE_ARN="$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.Arn' --output text)"

# 4. GitHub repository variables (NOT secrets — no credentials involved) -----
set_gh_var() {
  local name="$1" value="$2"
  # gh >= 2.40 has `gh variable`; older releases need the REST API.
  if gh variable set "$name" --body "$value" --repo "$REPO" >/dev/null 2>&1; then
    return 0
  fi
  if gh api -X POST "repos/$REPO/actions/variables" \
       -f name="$name" -f value="$value" >/dev/null 2>&1; then
    return 0
  fi
  # Already exists -> update it.
  gh api -X PATCH "repos/$REPO/actions/variables/$name" \
       -f name="$name" -f value="$value" >/dev/null 2>&1
}

set_gh_vars() {
  set_gh_var AWS_REGION      "$REGION" &&
  set_gh_var AWS_ROLE_ARN    "$ROLE_ARN" &&
  set_gh_var EC2_INSTANCE_ID "$INSTANCE_ID"
}

echo
if command -v gh >/dev/null 2>&1 && set_gh_vars 2>/dev/null; then
  echo "[setup] GitHub repository variables set automatically"
else
  echo "[setup] Set these three repository variables (Settings > Secrets and"
  echo "        variables > Actions > Variables), or run with gh logged in:"
  echo "  gh variable set AWS_REGION --body \"$REGION\" --repo $REPO"
  echo "  gh variable set AWS_ROLE_ARN --body \"$ROLE_ARN\" --repo $REPO"
  echo "  gh variable set EC2_INSTANCE_ID --body \"$INSTANCE_ID\" --repo $REPO"
fi

echo
echo "[setup] done. Verify SSM registration (can take a minute):"
echo "  aws ssm describe-instance-information --query 'InstanceInformationList[].InstanceId' --output text"
echo "[setup] Then push to $BRANCH — .github/workflows/deploy-ec2.yml deploys automatically."
