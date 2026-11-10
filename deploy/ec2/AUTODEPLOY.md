# AWS EC2 — launch + automatic deploys on every GitHub push

**Goal:** `git push origin main` → AWS updates itself. No manual steps.

> **TL;DR — three commands, then you are done.**
> ```bash
> # 1. Launch the instance (from the repo root, with AWS CLI configured)
> aws ec2 run-instances ... --user-data file://deploy/ec2/user-data.sh   # full command in STEP 1
>
> # 2. On the instance, enable auto-deploy (one command, zero configuration)
> sudo bash /opt/btc-hunt/deploy/ec2/enable-autopull.sh
>
> # 3. From then on, just push — the instance deploys within ~2 minutes
> git push origin main
> ```
> Want **instant** (seconds, not ~2 min)? Use STEP 2 **Option B** instead — one
> setup script plus a GitHub Actions workflow.

---

## What you get

| | Option A — auto-pull timer | Option B — GitHub Actions → SSM |
| --- | --- | --- |
| Setup | **1 command on the instance** | 1 AWS setup script + 3 repo variables |
| Trigger | polls `main` every 2 min | every push to `main` |
| Delay | ~2 minutes | seconds |
| GitHub secrets | none | none (OIDC short-lived creds) |
| Inbound ports from CI | none | none (AWS SSM) |
| AWS IAM setup | none | OIDC role + SSM instance profile (scripted) |

Both run the same single deploy command: **`sudo btc-hunt-update`**. It fetches
`main`, re-runs the idempotent installer (systemd + nginx + venv), restarts the
service and checks `/health`. If the instance is already on the latest commit
and healthy, it does nothing — so no pointless restarts.

---

## STEP 1 — Launch the EC2 instance (one time)

Run from the **repo root** on your laptop, with the AWS CLI configured. (Full
walkthrough and the console equivalent: [README.md](README.md#option-a--launch-with-the-aws-cli).)

```bash
REGION=us-east-1
VPC_ID=vpc-xxxxxxxxxxxxxxxxx
SUBNET_ID=subnet-xxxxxxxxxxxxxxxxx      # public subnet
KEY_NAME=my-keypair
MY_IP="$(curl -s https://checkip.amazonaws.com)/32"

SG_ID=$(aws ec2 create-security-group --region "$REGION" \
  --group-name btc-hunt-sg --description "BTC Hunt dashboard" \
  --vpc-id "$VPC_ID" --query GroupId --output text)
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 22 --cidr "$MY_IP"
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 80 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 443 --cidr 0.0.0.0/0

AMI_ID=$(aws ssm get-parameter --region "$REGION" \
  --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
  --query Parameter.Value --output text)

INSTANCE_ID=$(aws ec2 run-instances --region "$REGION" \
  --image-id "$AMI_ID" --instance-type t3.small --key-name "$KEY_NAME" \
  --security-group-ids "$SG_ID" --subnet-id "$SUBNET_ID" \
  --associate-public-ip-address \
  --block-device-mappings '[{"DeviceName":"/dev/sdf","Ebs":{"VolumeSize":20,"VolumeType":"gp3","Encrypted":true,"DeleteOnTermination":false}}]' \
  --metadata-options 'HttpTokens=required,HttpEndpoint=enabled' \
  --user-data file://deploy/ec2/user-data.sh \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=btc-hunt}]' \
  --query 'Instances[0].InstanceId' --output text)

aws ec2 wait instance-status-ok --region "$REGION" --instance-ids "$INSTANCE_ID"
PUBLIC_IP=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
curl -fsS "http://$PUBLIC_IP/health"     # -> {"status":"ok"}
```

`user-data.sh` clones `main`, installs systemd + nginx, and installs the deploy
command at `/usr/local/bin/btc-hunt-update`. Bootstrap log:
`/var/log/btc-hunt-bootstrap.log`.

Then do the two one-time security steps from [README.md](README.md#after-boot):
set `APP_USER`/`APP_PASSWORD` in `/etc/btc-hunt.env` and enable HTTPS.

---

## STEP 2 — Turn on automatic deploys (pick ONE option)

### Option A — simplest: one command on the instance

```bash
sudo bash /opt/btc-hunt/deploy/ec2/enable-autopull.sh
```

That installs a systemd timer which runs `btc-hunt-update` every 2 minutes.
**Push to `main` → deployed within ~2 minutes, forever.** No GitHub secrets,
no IAM roles, no inbound ports, nothing to rotate.

Useful commands:

```bash
systemctl list-timers btc-hunt-autopull.timer          # next run
sudo journalctl -u btc-hunt-autopull.service -f        # deploy log
sudo systemctl disable --now btc-hunt-autopull.timer   # turn it off
```

### Option B — instant: GitHub Actions → AWS SSM

The workflow [`.github/workflows/deploy-ec2.yml`](../../.github/workflows/deploy-ec2.yml)
fires on every push to `main` (and via `workflow_dispatch`). It assumes a
short-lived OIDC role, then sends `sudo /usr/local/bin/btc-hunt-update` to the
instance over **AWS Systems Manager Run Command** — no SSH keys, no AWS access
keys, no inbound firewall rules for GitHub runners.

1. **The workflow file must be on `main`.** If it is only on a feature branch,
   merge that PR first (or push it to `main`). GitHub only runs `push: main`
   workflows from the `main` copy.

2. **Run the one-shot AWS setup** from your laptop (AWS CLI + `gh` logged in):

   ```bash
   EC2_INSTANCE_ID=i-0abc123def456789 AWS_REGION=us-east-1 \
     bash deploy/ec2/setup-autodeploy.sh
   ```

   It creates the GitHub OIDC provider, a least-privilege role scoped to
   `repo:Phaviwylera/edurep:ref:refs/heads/main`, attaches an
   `AmazonSSMManagedInstanceCore` instance profile to your EC2 instance, and
   sets the three repository variables (`AWS_REGION`, `AWS_ROLE_ARN`,
   `EC2_INSTANCE_ID`). It prints the `gh variable set` commands if `gh` is not
   available, and falls back to the REST API on older `gh` releases. Safe to
   re-run.

   **Until those variables exist the workflow is skipped, not failed** — so if
   you chose Option A you never see a red X and need no GitHub setup at all.

3. **Verify the instance is SSM-managed** (can take a minute after attaching
   the profile):

   ```bash
   aws ssm describe-instance-information \
     --query 'InstanceInformationList[].InstanceId' --output text
   ```

   Canonical Ubuntu 24.04 AMIs include the SSM agent. If the instance is not
   listed: `sudo snap install amazon-ssm-agent --classic` on the instance and
   check `sudo systemctl status snap.amazon-ssm-agent.amazon-ssm-agent.service`.

> The workflow ignores `**/*.md` changes, so documentation-only pushes do not
> restart the app. Remove `paths-ignore` if you want every push to deploy.

---

## STEP 3 — Verify it really is hands-free

```bash
# on your laptop
git commit -am "test auto deploy" && git push origin main

# Option A: watch the instance pick it up
sudo journalctl -u btc-hunt-autopull.service -f

# Option B: watch the workflow
# https://github.com/Phaviwylera/edurep/actions

# from anywhere
curl -fsS "http://$PUBLIC_IP/health"     # {"status":"ok"}
```

To confirm the running commit:

```bash
sudo git -C /opt/btc-hunt log -1 --oneline
```

---

## Deploy commands (reference)

| Task | Command |
| --- | --- |
| **Deploy latest `main` now** | `sudo btc-hunt-update` |
| Trigger the workflow by hand | `gh workflow run deploy-ec2.yml --repo Phaviwylera/edurep` |
| Check last deploy (Option A) | `sudo journalctl -u btc-hunt-autopull.service -n 50` |
| Check last deploy (Option B) | `gh run list --workflow deploy-ec2.yml --repo Phaviwylera/edurep` |
| App logs | `sudo journalctl -u btc-hunt -f` |
| Restart only | `sudo systemctl restart btc-hunt` |
| Force a re-run of the installer | `sudo bash /opt/btc-hunt/deploy/ec2/install.sh` |
| Disable auto-deploy (Option A) | `sudo systemctl disable --now btc-hunt-autopull.timer` |

`btc-hunt-update` is installed at a path **outside** the git checkout on
purpose: it safely `git reset --hard`s `/opt/btc-hunt` while running, and
re-installs its own newest version on every deploy.

---

## Links

- [Full EC2 launch guide](README.md)
- [GitHub Actions workflow](../../.github/workflows/deploy-ec2.yml)
- [Deploy command source](update.sh)
- [One-shot AWS setup script](setup-autodeploy.sh)
- [Auto-pull timer](btc-hunt-autopull.timer) · [enable script](enable-autopull.sh)
- [GitHub Actions dashboard](https://github.com/Phaviwylera/edurep/actions)
- [Repository variables](https://github.com/Phaviwylera/edurep/settings/variables/actions)

---

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Workflow shows `skipped` | The three repo variables are not set yet — run `setup-autodeploy.sh` (Option B), or ignore it entirely if you use Option A |
| Workflow does not appear at all | The workflow file is not on `main` yet — merge the PR. Also check `paths-ignore: '**/*.md'` |
| `Not authorized to perform sts:AssumeRoleWithWebIdentity` | Re-run `setup-autodeploy.sh`; confirm the repo/branch in the trust policy and `id-token: write` in the workflow |
| Missing repository variable | `gh variable set AWS_REGION --body us-east-1 --repo Phaviwylera/edurep` (same for `AWS_ROLE_ARN`, `EC2_INSTANCE_ID`) |
| SSM command stays `Pending` | Instance not SSM-managed: check the instance profile and `snap.amazon-ssm-agent.amazon-ssm-agent.service` |
| Deploy fails with `Failed` | Workflow prints `StandardErrorContent`; on the instance `sudo btc-hunt-update` to reproduce |
| Auto-pull timer does nothing | `systemctl status btc-hunt-autopull.timer`; `sudo journalctl -u btc-hunt-autopull.service -n 50` |
| `/health` still 502 | `sudo systemctl status btc-hunt nginx`, `sudo nginx -t` |
