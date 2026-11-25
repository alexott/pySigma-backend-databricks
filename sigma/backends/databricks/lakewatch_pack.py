"""Identifiers for Lakewatch content-pack documents."""

from uuid import NAMESPACE_URL, uuid5

CONTENT_RESOURCE_NAMESPACE = uuid5(
    NAMESPACE_URL, "https://github.com/alexott/databricks-sigma-backend#lakewatch-content-resource")


def content_resource_id(sigma_id: str, profile: str) -> str:
    """Stable content_resource_id of the rule converted for a profile (from the Sigma id)."""
    return str(uuid5(CONTENT_RESOURCE_NAMESPACE, f"{sigma_id.lower()}:{profile}"))
