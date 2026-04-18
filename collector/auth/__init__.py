"""
Windows Authentication Collector Module

This module provides specialized collection of Windows authentication events
for UEBA (User and Entity Behavior Analytics) processing.
"""

from .windows_auth_collector import WindowsAuthCollector

__all__ = ["WindowsAuthCollector"]
