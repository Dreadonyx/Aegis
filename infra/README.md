# Aegis on AWS

A short-lived Internet honeypot deployment of Aegis, paid for entirely by AWS Free plan credits. It collects real Cowrie telemetry (PENDING item 1) and runs a CPU Ollama model for live AI validation (PENDING item 2).

## Deployment

| | |
| --- | --- |
| Stack | `AegisStack` (CDK, Python), us-east-1, account <aws-account-id> |
| Deployed | 2026-10-09 |
| Instance | `<instance-id>`, m7i-flex.large (2 vCPU, 8 GB), Amazon Linux 2023, 40 GB gp3 encrypted |
| Honeypot | `<honeypot-public-ip>:22` (Cowrie, public) |
| Dashboard | `127.0.0.1:8000` on the instance, SSM tunnel only |
| Raw log bucket | `<log-bucket>` (hourly sync, retained on stack delete) |
| AI | Ollama 0.34.3, `llama3.2:3b` (active) and `llama3.2:1b`, 240 s timeout |
| Budget alert | `account-monthly-usage`: email at 80% of $120/month gross usage, actual or forecast |

The public IP is not an Elastic IP; it changes if the instance is stopped and started.

## Cost and deadline

The account is on the AWS **Free plan**. Usage is paid from credits ($174.58 on 2026-10-09), and the plan cannot charge a card. **The plan and credits expire on 2026-10-30.** After that the account must be upgraded to the Paid plan (usage is then billed) or it is closed.

| Item | Rate | To 2026-10-30 (21 days) |
| --- | --- | --- |
| m7i-flex.large on-demand | $0.09576/h | |
| Public IPv4 | $0.005/h | |
| 40 GB gp3 | $0.08/GB-month | |
| **Aegis total** | **~$2.52/day** | **~$53** |
| Existing Certflow and portfolio workloads | ~$0.98/day | ~$21 |

S3 log storage and the budget are negligible. There is no NAT gateway or load balancer.

**Tear down by 2026-10-28** (see below).

## Architecture

```
Internet ──tcp/22──▶ SG ──▶ host :22 ──DNAT──▶ cowrie (honeypot net 172.30.0.0/24)
                                                     │ JSONL
                                                     ▼
                                          cowrie-log volume ──▶ dashboard (127.0.0.1:8000)
                                                     │                 │ loopback
                                          hourly s3 sync               ▼
                                                     ▼         ollama (shares dashboard netns)
                                               S3 log bucket
You ──SSM port forward──▶ 127.0.0.1:8000
```

- Compose runs `compose.yaml` plus `deploy/compose.aws.yaml`. The overlay publishes Cowrie on host port 22, drops the local SSH relay, adds Ollama in the dashboard's network namespace, and sets restart policies.
- Docker publishing keeps the attacker's real source address, which the local relay topology could not.
- Host `sshd` is disabled. There is no key pair. Administration is SSM Session Manager only.

### Containment

- `aegis-firewall.service` runs before Docker and adds `DOCKER-USER` rules:
  - honeypot network: replies to inbound connections only, every new outbound connection dropped;
  - all containers: `169.254.169.254` (instance metadata) dropped.
- IMDSv2 required with hop limit 1, so metadata tokens cannot reach containers.
- The instance role can use SSM, read the CDK asset bucket, and write the log bucket. Nothing else.
- Cowrie keeps its base hardening: emulated shell, no forwarding, no Telnet, all capabilities dropped, memory and PID limits.

### Verified after deploy (2026-10-09)

- First boot completed; `cowrie`, `dashboard` (healthy) and `ollama` running with restart policies.
- Host listens only on `:22` (Cowrie via Docker) and `127.0.0.1:8000`; `sshd` inactive.
- `llama3.2:3b` and `llama3.2:1b` installed.
- Outbound connection from the Cowrie container to `1.1.1.1:443` timed out (blocked).
- IMDSv2 token request from the dashboard container timed out (blocked).
- External connection to port 22 was logged by Cowrie with the real client address and imported by the dashboard.
- Hourly log sync timer scheduled.

## Access

Install the Session Manager plugin first (`aws-session-manager-plugin` on the AUR).

```bash
# Dashboard: then open http://127.0.0.1:8000
aws ssm start-session --region us-east-1 --target <instance-id> \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8000"],"localPortNumber":["8000"]}'

# Shell on the instance
aws ssm start-session --region us-east-1 --target <instance-id>

# Useful on the instance
sudo tail -f /var/log/aegis-init.log
cd /opt/aegis && sudo docker compose -p aegis -f compose.yaml -f deploy/compose.aws.yaml ps
sudo iptables -S DOCKER-USER
```

To switch AI models, change `AEGIS_OLLAMA_MODEL` in `/opt/aegis/deploy/compose.aws.yaml` on the instance and run `docker compose ... up -d dashboard`.

## Known limits

- The dashboard stops importing at its **50,000-event limit**, which an Internet honeypot can reach within days. Collection status then reads "Waiting for ... available storage". Raw Cowrie logs keep everything and are the evaluation dataset.
- Outbound connections from Cowrie are blocked, so attacker downloads fail and the **completed-download rule will not fire** on live traffic.
- Raw logs contain real attacker addresses and attempted credentials. Treat the volume, bucket, and any local copies as sensitive.
- Changing the source bundle and redeploying updates user data but does not rerun it. Redeploy the code on the instance manually or replace the instance.

## Deploy, download, tear down

```bash
cd infra
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cdk diff AegisStack -c alertEmail=<address>
cdk deploy AegisStack -c alertEmail=<address>
```

The alert address is supplied at deploy time and is intentionally not stored in the repository.

Before 2026-10-28, download the data and remove everything:

```bash
# 1. Final log sync, then download raw logs
aws ssm send-command --region us-east-1 --instance-ids <instance-id> \
  --document-name AWS-RunShellScript --parameters 'commands=["/usr/local/sbin/aegis-log-sync"]'
aws s3 sync s3://<log-bucket> ./aws-cowrie-logs

# 2. Optional: export reports and evidence from the dashboard

# 3. Delete the stack, then the retained bucket
cdk destroy AegisStack
aws s3 rb s3://<log-bucket> --force
```
