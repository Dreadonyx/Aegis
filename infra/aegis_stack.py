import aws_cdk as cdk
from aws_cdk import (
    Stack,
    CfnOutput,
    aws_budgets as budgets,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_s3 as s3,
    aws_s3_assets as s3_assets,
)
from constructs import Construct
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_VERSION = "v2.29.7"
BUILDX_VERSION = "v0.17.1"
HONEYPOT_SUBNET = "172.30.0.0/24"  # must match deploy/compose.aws.yaml
OLLAMA_MODELS = ["llama3.2:3b", "llama3.2:1b"]

# Everything outside the image build context stays local.
ASSET_EXCLUDES = [
    "infra", ".git", ".venv", "data", "docs", "tests", "test-results",
    "__pycache__", "**/__pycache__", ".pytest_cache", "fixtures",
]

# Applied before Docker starts so containers never run unfiltered. Docker
# keeps an existing DOCKER-USER chain. Honeypot containers may only answer
# inbound connections; no container may reach instance metadata.
FIREWALL = f"""#!/bin/bash
set -euo pipefail
iptables -N DOCKER-USER 2>/dev/null || true
rule() {{ iptables -C DOCKER-USER "$@" 2>/dev/null || iptables -I DOCKER-USER "$@"; }}
rule -s {HONEYPOT_SUBNET} -j DROP
rule -s {HONEYPOT_SUBNET} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
rule -d 169.254.169.254/32 -j DROP
"""


def bootstrap_script(bucket: str, key: str, log_bucket: str) -> str:
    # Runs once at first boot as root.
    # Model pulls retry while Ollama starts; a failure must not stop the log sync setup.
    pulls = "\n".join(
        f"for i in $(seq 30); do docker compose $COMPOSE exec -T ollama ollama pull {m} && break; sleep 10; done || true"
        for m in OLLAMA_MODELS
    )
    return f"""#!/bin/bash
set -euo pipefail
exec > >(tee /var/log/aegis-init.log) 2>&1

echo "=== Freeing port 22 for Cowrie (admin access is SSM only) ==="
systemctl disable --now sshd.service sshd.socket 2>/dev/null || true

echo "=== Installing Docker ==="
dnf install -y docker unzip
mkdir -p /usr/local/lib/docker/cli-plugins
curl -fsSL "https://github.com/docker/compose/releases/download/{COMPOSE_VERSION}/docker-compose-linux-x86_64" \\
  -o /usr/local/lib/docker/cli-plugins/docker-compose
curl -fsSL "https://github.com/docker/buildx/releases/download/{BUILDX_VERSION}/buildx-{BUILDX_VERSION}.linux-amd64" \\
  -o /usr/local/lib/docker/cli-plugins/docker-buildx
chmod +x /usr/local/lib/docker/cli-plugins/*

echo "=== Container egress firewall ==="
cat > /usr/local/sbin/aegis-firewall <<'FW'
{FIREWALL}FW
chmod 755 /usr/local/sbin/aegis-firewall
cat > /etc/systemd/system/aegis-firewall.service <<'UNIT'
[Unit]
Description=Aegis container egress firewall
Before=docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/aegis-firewall
[Install]
WantedBy=multi-user.target docker.service
UNIT
systemctl daemon-reload
systemctl enable --now aegis-firewall.service
systemctl enable --now docker

echo "=== Fetching Aegis source ==="
rm -rf /opt/aegis && mkdir -p /opt/aegis
aws s3 cp "s3://{bucket}/{key}" /tmp/aegis.zip
unzip -q /tmp/aegis.zip -d /opt/aegis

echo "=== Starting the lab ==="
cd /opt/aegis
COMPOSE="-p aegis -f compose.yaml -f deploy/compose.aws.yaml"
docker compose $COMPOSE up -d --build
{pulls}

echo "=== Hourly Cowrie log sync to S3 ==="
cat > /usr/local/sbin/aegis-log-sync <<'SYNC'
#!/bin/bash
set -euo pipefail
src=$(docker volume inspect -f '{{{{.Mountpoint}}}}' aegis_cowrie-log)
aws s3 sync "$src" "s3://{log_bucket}/cowrie/$(hostname)/" --only-show-errors
SYNC
chmod 755 /usr/local/sbin/aegis-log-sync
cat > /etc/systemd/system/aegis-log-sync.service <<'UNIT'
[Unit]
Description=Copy Cowrie logs to S3
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/aegis-log-sync
UNIT
cat > /etc/systemd/system/aegis-log-sync.timer <<'UNIT'
[Unit]
Description=Hourly Cowrie log sync
[Timer]
OnCalendar=hourly
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now aegis-log-sync.timer
echo "=== Bootstrap complete ==="
"""


class AegisStack(Stack):
    def __init__(self, scope: Construct, id: str, *, alert_email: str | None = None, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # ── Dedicated VPC: one public subnet, no NAT gateway ───────────────
        vpc = ec2.Vpc(
            self,
            "AegisVpc",
            max_azs=1,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(name="public", subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=24)
            ],
        )

        # ── Security group: only the honeypot port is open ─────────────────
        sg = ec2.SecurityGroup(
            self,
            "AegisSG",
            vpc=vpc,
            description="Aegis honeypot - Cowrie on 22, admin via SSM only",
            allow_all_outbound=True,
        )
        sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22), "Cowrie SSH honeypot")

        # ── Raw Cowrie logs, kept after the stack is deleted ───────────────
        log_bucket = s3.Bucket(
            self,
            "AegisLogs",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        # ── Source bundle ──────────────────────────────────────────────────
        source = s3_assets.Asset(self, "AegisSource", path=str(PROJECT_ROOT), exclude=ASSET_EXCLUDES)

        # ── IAM role: SSM, source read, log upload ─────────────────────────
        role = iam.Role(
            self,
            "AegisInstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")],
        )
        source.grant_read(role)
        log_bucket.grant_put(role)
        log_bucket.grant_read(role)  # aws s3 sync lists the destination

        # ── EC2 instance ───────────────────────────────────────────────────
        instance = ec2.Instance(
            self,
            "AegisInstance",
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            associate_public_ip_address=True,
            instance_type=ec2.InstanceType("m7i-flex.large"),
            # Pinned in cdk.context.json so a newer AMI never replaces the honeypot.
            machine_image=ec2.MachineImage.latest_amazon_linux2023(cached_in_context=True),
            security_group=sg,
            role=role,
            user_data=ec2.UserData.custom(
                bootstrap_script(source.s3_bucket_name, source.s3_object_key, log_bucket.bucket_name)
            ),
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/xvda",
                    volume=ec2.BlockDeviceVolume.ebs(40, volume_type=ec2.EbsDeviceVolumeType.GP3, encrypted=True),
                )
            ],
        )
        # IMDSv2 only, hop limit 1: metadata tokens cannot cross into containers.
        metadata_template = ec2.LaunchTemplate(
            self,
            "AegisMetadataOptions",
            require_imdsv2=True,
            http_put_response_hop_limit=1,
        )
        instance.instance.add_property_override("LaunchTemplate", {
            "LaunchTemplateId": metadata_template.launch_template_id,
            "Version": metadata_template.latest_version_number,
        })
        cdk.Tags.of(self).add("project", "aegis")

        # ── Budget alert on gross usage (credits excluded) ─────────────────
        if alert_email:
            budgets.CfnBudget(
                self,
                "AegisAccountBudget",
                budget=budgets.CfnBudget.BudgetDataProperty(
                    budget_name="account-monthly-usage",
                    budget_type="COST",
                    time_unit="MONTHLY",
                    budget_limit=budgets.CfnBudget.SpendProperty(amount=120, unit="USD"),
                    cost_types=budgets.CfnBudget.CostTypesProperty(include_credit=False, include_refund=False),
                ),
                notifications_with_subscribers=[
                    budgets.CfnBudget.NotificationWithSubscribersProperty(
                        notification=budgets.CfnBudget.NotificationProperty(
                            notification_type=notification_type,
                            comparison_operator="GREATER_THAN",
                            threshold=80,
                            threshold_type="PERCENTAGE",
                        ),
                        subscribers=[budgets.CfnBudget.SubscriberProperty(subscription_type="EMAIL", address=alert_email)],
                    )
                    for notification_type in ("ACTUAL", "FORECASTED")
                ],
            )

        # ── Outputs ────────────────────────────────────────────────────────
        CfnOutput(self, "InstanceId", value=instance.instance_id, description="EC2 instance ID")
        CfnOutput(self, "HoneypotIP", value=instance.instance_public_ip, description="Cowrie listens on port 22 here")
        CfnOutput(self, "LogBucket", value=log_bucket.bucket_name, description="Hourly copy of raw Cowrie logs")
        CfnOutput(
            self,
            "DashboardTunnel",
            value=cdk.Fn.join("", [
                "aws ssm start-session --region ", self.region, " --target ", instance.instance_id,
                " --document-name AWS-StartPortForwardingSession",
                ' --parameters \'{"portNumber":["8000"],"localPortNumber":["8000"]}\'',
            ]),
            description="Then open http://127.0.0.1:8000",
        )
