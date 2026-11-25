"""Tests for resolving Sigma field names against parser schemas."""

import re

import pytest

from sigma.backends.databricks.field_paths import (
    JOIN_PREFIX,
    FieldPath,
    UnknownFieldError,
    join_field_name,
    resolve_schema_path,
)
from sigma.backends.databricks.ocsf_fields import OcsfPath
from sigma.backends.databricks.schema_catalog import ParserSchema, PathInfo


def _p(type_, storage, element=None):
    return PathInfo(type=type_, storage=storage, element=element)


SCHEMA = ParserSchema("p1", "u-1", 2, {
    "eventName": _p("STRING", "column"),
    "EventID": PathInfo(type="STRING", storage="column", allowed=("1", "7")),
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
    "EventData": _p("VARIANT", "column"),
    "Data": _p("ARRAY", "column", "STRUCT"),
    "Data[]._Name": _p("STRING", "struct"),
    "Data[]._VALUE": _p("STRING", "struct"),
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


def test_resolve_named_entry_of_variant():
    r = resolve_schema_path(SCHEMA, "EventData[Image]")
    assert r == FieldPath((), ("EventData",), (), None, "STRING", entry="Image", entry_variant=True)
    assert r.whole_variant is False


def test_resolve_named_entry_of_array_of_struct():
    r = resolve_schema_path(SCHEMA, "data[QueryName]")      # column name ignores case
    assert r == FieldPath((), ("Data",), (), None, "STRING", entry="QueryName", entry_variant=False)


def test_resolve_unnamed_data_of_variant():
    r = resolve_schema_path(SCHEMA, "EventData[*]")
    assert r == FieldPath((), ("EventData",), (), None, "STRING", entry="*", entry_variant=True)


@pytest.mark.parametrize("path", ["data[*]", "eventName[*]", "userIdentity.arn[*]"])
def test_resolve_unnamed_data_needs_whole_variant(path):
    with pytest.raises(UnknownFieldError, match=re.escape("'[*]' needs a whole VARIANT")):
        resolve_schema_path(SCHEMA, path)


@pytest.mark.parametrize("path, reason", [
    ("eventName[Image]", "needs a VARIANT or ARRAY<STRUCT<_Name, _VALUE>> field"),
    ("userIdentity.arn[Image]", "needs a VARIANT or ARRAY<STRUCT<_Name, _VALUE>> field"),
    ("target[Image]", "needs a VARIANT or ARRAY<STRUCT<_Name, _VALUE>> field"),
    ("resources[Image]", "needs a VARIANT or ARRAY<STRUCT<_Name, _VALUE>> field"),
    ("nosuch[Image]", "'nosuch' is not a declared field"),
])
def test_resolve_named_entry_fails(path, reason):
    with pytest.raises(UnknownFieldError, match=re.escape(reason)):
        resolve_schema_path(SCHEMA, path)


def test_ocsf_path_is_field_path():
    assert OcsfPath is FieldPath
    assert OcsfPath((), ("a",), ()).json_type is None


def test_allowed_on_column():
    assert resolve_schema_path(SCHEMA, "EventID").allowed == ("1", "7")
    assert resolve_schema_path(SCHEMA, "eventName").allowed is None


def test_undeclared_allowed():
    r = resolve_schema_path(SCHEMA, "userIdentity.custom.x", allow_undeclared=True)
    assert r.leaf == ("userIdentity",)
    assert r.json_path == ("custom", "x")
    assert r.json_type is None
    with pytest.raises(UnknownFieldError):
        resolve_schema_path(SCHEMA, "userIdentity.custom.x")


def test_undeclared_keeps_case_correction_of_declared_prefix():
    with pytest.warns(UserWarning, match="declared 'sessionContext'"):
        r = resolve_schema_path(SCHEMA, "userIdentity.SESSIONCONTEXT.extra", allow_undeclared=True)
    assert r.json_path == ("sessionContext", "extra")
    assert r.json_type is None


def test_join_resolves_parts():
    name = join_field_name("\\", ["eventName", "userIdentity.arn"])
    assert name.startswith(JOIN_PREFIX)
    r = resolve_schema_path(SCHEMA, name)
    assert r.join_sep == "\\"
    assert r.join[0].leaf == ("eventName",)
    assert r.join[1].json_path == ("arn",)


def test_join_with_plain_field_part_is_not_a_named_entry():
    # The name ends in ']' and would match the named-entry pattern.
    name = join_field_name("\\", ["eventName", "actor.alternateId"])
    assert name.endswith("]")
    r = resolve_schema_path(SCHEMA, name)
    assert r.entry is None and len(r.join) == 2


@pytest.mark.parametrize("part", [
    "resources.arn", "userIdentity", "actor", "EventData[Foo]",
    join_field_name("-", ["eventName", "EventID"]),
])
def test_join_rejects_non_scalar_part(part):
    with pytest.raises(UnknownFieldError, match="join parts must be scalar"):
        resolve_schema_path(SCHEMA, join_field_name("\\", ["eventName", part]))


def test_join_needs_two_parts():
    with pytest.raises(UnknownFieldError, match="join parts must be scalar"):
        resolve_schema_path(SCHEMA, join_field_name("-", ["eventName"]))


def test_join_allows_undeclared_when_flagged():
    name = join_field_name("-", ["eventName", "userIdentity.custom"])
    with pytest.raises(UnknownFieldError):
        resolve_schema_path(SCHEMA, name)
    assert resolve_schema_path(SCHEMA, name, allow_undeclared=True).join[1].json_path == ("custom",)
