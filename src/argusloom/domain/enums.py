"""Enum definitions for ArgusLoom graph nodes and threat attributes."""

from __future__ import annotations

from enum import Enum


class NodeKind(str, Enum):
    """Graph node categories used by the infrastructure model."""

    COMPUTE = "compute"
    STORAGE = "storage"
    NETWORK = "network"
    IAM = "iam"
    DATA = "data"
    EXTERNAL = "external"


class Criticality(str, Enum):
    """Risk criticality for infrastructure assets."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    # Backward-compatible lowercase aliases used in the acceptance tests.
    low = LOW
    medium = MEDIUM
    high = HIGH
    critical = CRITICAL


class StrideCategory(str, Enum):
    """STRIDE categories mapped to nodes during enrichment."""

    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"
