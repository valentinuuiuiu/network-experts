"""
Network Experts Team - A specialized collection of AI agents for network management
"""

__version__ = "0.1.0"
__author__ = "Network Experts Team"

# Ensure agents.py exists in the same directory as this __init__.py
try:
    from .agents import (
        ScannerBrother,
        SecurityBrother, 
        MonitorBrother,
        ConfigBrother,
        TroubleshootBrother
    )
except ImportError:
    # If relative import fails, raise the error to notify about the missing module
    raise

from .team import NetworkExpertsTeam # type: ignore
from .handlers import (
    DiagnosticsHandler
)

def info(self):
    return "NetworkExpertsTeam"

__all__ = [
    "ScannerBrother",
    "SecurityBrother", 
    "MonitorBrother",
    "ConfigBrother",
    "TroubleshootBrother",
    "NetworkExpertsTeam",
    "NetworkScanHandler",
    "DiagnosticsHandler"
]
