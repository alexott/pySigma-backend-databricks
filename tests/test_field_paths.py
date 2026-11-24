"""Tests for resolving Sigma field names against parser schemas."""

import pytest

from sigma.backends.databricks.field_paths import (
    FieldPath,
    UnknownFieldError,
    resolve_schema_path,
)
from sigma.backends.databricks.ocsf_fields import OcsfPath
from sigma.backends.databricks.schema_catalog import ParserSchema, PathInfo


def _p(type_, storage, element=None):
    return PathInfo(type=type_, storage=storage, element=element)


SCHEMA = ParserSchema("p1", "u-1", 2, {
    "eventName": _p("STRING", "column"),
    "actor": _p("STRUCT", "column"),
    "actor.alternateId": _p("STRING", "struct"),
    "userIdentity": _p("VARIANT", "column"),
    "userIdentity.arn": _p("STRING", "variant"),
    "userIdentity.sessionContext": _p("STRUCT", "variant"),
    "userIdentity.sessionContext.mfa": _p("STRING", "variant"),
    "userIdentity.tags": _p("ARRAY", "variant", "STRING"),
    "requestParameters": _p("VARIANT", "column"),
    "resources": _p("ARRAY", "column", "VARIANT"),
    "resources[].arn": _p("STRING", "variant"),
    "filemod_hash": _p("ARRAY", "column", "STRING"),
    "target": _p("ARRAY", "column", "STRUCT"),
    "target[].displayName": _p("STRING", "struct"),
    "debugContext": _p("STRUCT", "column"),
    "debugContext.debugData": _p("VARIANT", "struct"),
})


def test_resolve_column():
    assert resolve_schema_path(SCHEMA, "eventName") == FieldPath((), ("eventName",), (), None, "STRING")


def test_resolve_struct_case_insensitive():
    r = resolve_schema_path(SCHEMA, "actor.alternateid")
    assert r.leaf == ("actor", "alternateId")
    assert r.leaf_type == "STRING"


def test_resolve_declared_variant():
    r = resolve_schema_path(SCHEMA, "userIdentity.arn")
    assert (r.leaf, r.json_path, r.json_type, r.leaf_type) == (("userIdentity",), ("arn",), "STRING", None)


def test_resolve_nested_declared_variant():
    r = resolve_schema_path(SCHEMA, "userIdentity.sessionContext.mfa")
    assert r.json_path == ("sessionContext", "mfa")
    assert r.json_type == "STRING"


def test_resolve_variant_case_corrected():
    with pytest.warns(UserWarning, match="declared 'arn'"):
        r = resolve_schema_path(SCHEMA, "useridentity.ARN")
    assert r.leaf == ("userIdentity",)
    assert r.json_path == ("arn",)


def test_resolve_undeclared_under_declared_variant_fails():
    with pytest.raises(UnknownFieldError) as e:
        resolve_schema_path(SCHEMA, "userIdentity.nope")
    assert e.value.path == "userIdentity.nope"
    assert e.value.parser == "p1"
    assert "p1" in str(e.value) and "userIdentity.nope" in str(e.value)


def test_resolve_unknown_column_fails():
    with pytest.raises(UnknownFieldError):
        resolve_schema_path(SCHEMA, "nope")


def test_resolve_freeform_variant():
    r = resolve_schema_path(SCHEMA, "requestParameters.bucketName")
    assert r.leaf == ("requestParameters",)
    assert r.json_path == ("bucketName",)
    assert r.json_type is None


def test_resolve_array_of_variant():
    r = resolve_schema_path(SCHEMA, "resources.arn")
    assert r.arrays == (("resources",),)
    assert r.leaf == ()
    assert r.json_path == ("arn",)
    assert r.json_type == "STRING"


def test_resolve_array_of_scalars():
    r = resolve_schema_path(SCHEMA, "filemod_hash")
    assert r.arrays == (("filemod_hash",),)
    assert r.leaf == ()
    assert r.leaf_type == "STRING"


def test_resolve_array_of_struct_member():
    r = resolve_schema_path(SCHEMA, "target.displayName")
    assert r.arrays == (("target",),)
    assert r.leaf == ("displayName",)
    assert r.leaf_type == "STRING"


def test_resolve_variant_under_struct():
    r = resolve_schema_path(SCHEMA, "debugContext.debugData.requestUri")
    assert r.leaf == ("debugContext", "debugData")
    assert r.json_path == ("requestUri",)
    assert r.json_type is None


def test_resolve_whole_variant():
    assert resolve_schema_path(SCHEMA, "userIdentity").whole_variant is True
    assert resolve_schema_path(SCHEMA, "userIdentity.arn").whole_variant is False


def test_resolve_array_inside_variant_fails():
    with pytest.raises(UnknownFieldError, match="arrays inside VARIANT are not supported"):
        resolve_schema_path(SCHEMA, "userIdentity.tags")


def test_ocsf_path_is_field_path():
    assert OcsfPath is FieldPath
    assert OcsfPath((), ("a",), ()).json_type is None
