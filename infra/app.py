import os
import aws_cdk as cdk
from aegis_stack import AegisStack

app = cdk.App()

AegisStack(
    app,
    "AegisStack",
    alert_email=app.node.try_get_context("alertEmail"),
    env=cdk.Environment(
        account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
        region=os.environ.get("CDK_DEFAULT_REGION", "us-east-1"),
    ),
)

app.synth()
