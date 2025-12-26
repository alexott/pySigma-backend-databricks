from dataclasses import dataclass, field
from typing import Union, List, Dict, Callable

import inflection
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldFunctionTransformation


# Processing pipelines should be defined as functions that return a ProcessingPipeline object.
def snake_case() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Snake case names conversion pipeline",
        priority=20,  # The priority defines the order pipelines are applied. See documentation for common values.
        items=[
            ProcessingItem(  # Field mappings
                identifier="snake_case",
                transformation=FieldFunctionTransformation({}, inflection.underscore),
            )
        ],
    )
