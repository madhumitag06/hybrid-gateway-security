"""
Cloud Provider Adapters Package.
"""

from backend.app.cloud.adapters.aws.adapter import AwsCloudAdapter
from backend.app.cloud.adapters.azure.adapter import AzureCloudAdapter
from backend.app.cloud.adapters.docker_lab.adapter import DockerLabCloudAdapter
from backend.app.cloud.adapters.gcp.adapter import GcpCloudAdapter

__all__ = [
    "AwsCloudAdapter",
    "GcpCloudAdapter",
    "AzureCloudAdapter",
    "DockerLabCloudAdapter",
]

