"""Terraform ingestion parser for AWS infrastructure assets."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import hcl2

from argusloom.domain.enums import Criticality, NodeKind, StrideCategory
from argusloom.domain.graph import GraphEdge, GraphNode


def _normalize_tf_value(value: Any) -> Any:
    if isinstance(value, str):
        stripped = value.strip().strip('"')
        return stripped
    if isinstance(value, list):
        return [_normalize_tf_value(item) for item in value]
    return value


def _normalize_ref(ref: str) -> str:
    normalized = _normalize_tf_value(ref)
    if not isinstance(normalized, str):
        return ref
    normalized = normalized.replace("${", "").replace("}", "")
    for suffix in (".arn", ".id", ".name"):
        if normalized.endswith(suffix):
            return normalized.rsplit(suffix, 1)[0]
    if normalized.startswith("\"") and normalized.endswith("\""):
        return normalized.strip('"')
    return normalized


def _infer_criticality(resource_type: str, attributes: dict[str, Any]) -> Criticality:
    if resource_type in {"aws_db_instance", "aws_lambda_function"}:
        return Criticality.HIGH
    if resource_type in {"aws_security_group", "aws_api_gateway_rest_api"}:
        return Criticality.MEDIUM
    if resource_type in {"aws_instance", "aws_iam_role"}:
        return Criticality.HIGH
    if resource_type == "aws_s3_bucket":
        return Criticality.MEDIUM
    return Criticality.LOW


def _infer_stride(resource_type: str) -> list[StrideCategory]:
    if resource_type == "aws_security_group":
        return [StrideCategory.INFORMATION_DISCLOSURE, StrideCategory.ELEVATION_OF_PRIVILEGE]
    if resource_type == "aws_db_instance":
        return [StrideCategory.TAMPERING, StrideCategory.INFORMATION_DISCLOSURE]
    if resource_type == "aws_lambda_function":
        return [StrideCategory.ELEVATION_OF_PRIVILEGE]
    return []


def _infer_exposure(resource_type: str, attributes: dict[str, Any]) -> float:
    if resource_type == "aws_security_group":
        inbound = attributes.get("ingress", [])
        if inbound:
            return 0.8
        return 0.4
    if resource_type == "aws_api_gateway_rest_api":
        return 0.6
    if resource_type == "aws_instance":
        return 0.5
    if resource_type == "aws_s3_bucket":
        return 0.7
    return 0.2


def _resource_kind(resource_type: str) -> NodeKind:
    if resource_type.startswith("aws_iam"):
        return NodeKind.IAM
    if resource_type.startswith("aws_instance") or resource_type.startswith("aws_lambda"):
        return NodeKind.COMPUTE
    if resource_type.startswith("aws_security_group") or resource_type.startswith("aws_api_gateway"):
        return NodeKind.NETWORK
    if resource_type.startswith("aws_s3") or resource_type.startswith("aws_db"):
        return NodeKind.STORAGE if resource_type.startswith("aws_s3") else NodeKind.DATA
    return NodeKind.EXTERNAL


def _load_tf_files(root: Path) -> list[dict[str, Any]]:
    if not root.exists():
        return []

    resources: list[dict[str, Any]] = []
    for tf_file in sorted(root.glob("*.tf")):
        with tf_file.open("r", encoding="utf-8") as handle:
            parsed = hcl2.load(handle)
        blocks = parsed.get("resource", [])
        for resource_block in blocks:
            for resource_key, resource_items in resource_block.items():
                resource_type = str(resource_key).strip('"')
                if not isinstance(resource_items, dict):
                    continue
                for instance_name, attrs in resource_items.items():
                    if not isinstance(attrs, dict):
                        continue
                    cleaned_attrs = {}
                    for key, value in attrs.items():
                        if key == "__is_block__":
                            continue
                        cleaned_attrs[str(key).strip('"')] = _normalize_tf_value(value)
                    resources.append({
                        "type": resource_type,
                        "name": str(instance_name).strip('"'),
                        "attributes": cleaned_attrs,
                    })
    return resources


def parse_terraform_directory(path: str | Path) -> tuple[list[GraphNode], list[GraphEdge]]:
    """Parse a directory of Terraform files and return graph nodes and edges."""

    root = Path(path)
    resources = _load_tf_files(root)
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    if not resources:
        return nodes, edges

    for resource in resources:
        resource_type = resource["type"]
        resource_name = resource["name"]
        resource_id = f"{resource_type}.{resource_name}"
        attrs = resource["attributes"]
        node = GraphNode(
            id=resource_id,
            name=resource_name,
            kind=_resource_kind(resource_type),
            source="terraform",
            criticality=_infer_criticality(resource_type, attrs),
            exposure=_infer_exposure(resource_type, attrs),
            metadata={"resource_type": resource_type, "attributes": attrs},
            stride=_infer_stride(resource_type),
        )
        nodes.append(node)

        if resource_type == "aws_instance":
            security_groups = attrs.get("vpc_security_group_ids", [])
            if isinstance(security_groups, list):
                for group in security_groups:
                    ref = _normalize_ref(str(group))
                    if isinstance(ref, str) and ref.startswith("aws_security_group."):
                        edges.append(GraphEdge(source=ref, target=resource_id, relation="attached_to"))
        elif resource_type == "aws_lambda_function":
            role_ref = _normalize_ref(attrs.get("role", ""))
            if isinstance(role_ref, str) and role_ref.startswith("aws_iam_role"):
                edges.append(GraphEdge(source=role_ref, target=resource_id, relation="uses_role"))
        elif resource_type == "aws_security_group":
            for ingress_rule in attrs.get("ingress", []):
                if isinstance(ingress_rule, dict) and ingress_rule.get("cidr_blocks"):
                    edges.append(GraphEdge(source=resource_id, target="external.internet", relation="exposes"))

    node_ids = {node.id for node in nodes}
    for resource in resources:
        resource_type = resource["type"]
        resource_name = resource["name"]
        current_id = f"{resource_type}.{resource_name}"
        attrs = resource["attributes"]
        for value in attrs.values():
            refs: list[str] = []
            if isinstance(value, str):
                ref = _normalize_ref(value)
                if ref.startswith("aws_"):
                    refs.append(ref)
            elif isinstance(value, list):
                for item in value:
                    ref = _normalize_ref(str(item))
                    if isinstance(ref, str) and ref.startswith("aws_"):
                        refs.append(ref)
            for ref in refs:
                if ref in node_ids:
                    edges.append(GraphEdge(source=ref, target=current_id, relation="depends_on"))

    return nodes, edges
