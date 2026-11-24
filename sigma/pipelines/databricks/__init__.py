"""Databricks processing pipelines for pySigma."""

from .lakewatch.pipeline import build_profile_pipeline
from .snake_case import snake_case

pipelines = {
    "snake_case": snake_case,
}

__all__ = ["build_profile_pipeline", "pipelines", "snake_case"]
