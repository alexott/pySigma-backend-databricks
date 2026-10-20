"""Tests for OCSF array/free-form aware field rendering of the Databricks backend."""

import json

import pytest
from sigma.collection import SigmaCollection
from sigma.pipelines.ocsf import ocsf_pipeline

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.ocsf_fields import (
    ARRAY_ATTRIBUTES,
    FREE_FORM_ATTRIBUTES,
    OCSF_VERSION,
    OcsfPath,
    split_ocsf_path,
)


def _rule(selection: str, condition: str = "sel") -> SigmaCollection:
    return SigmaCollection.from_yaml(f"""
        title: Test
        status: test
        logsource:
            category: test_category
            product: test_product
        detection:
{selection}
            condition: {condition}
    """)


@pytest.fixture
def ocsf_backend():
    return DatabricksBackend(ocsf=True)


def test_attribute_tables_are_grounded():
    assert OCSF_VERSION == "1.9.0"
    assert {"hashes", "answers", "evidences", "resources", "x_forwarded_for"} <= ARRAY_ATTRIBUTES
    assert {"unmapped", "xattributes", "data"} <= FREE_FORM_ATTRIBUTES
    assert "file" not in ARRAY_ATTRIBUTES


@pytest.mark.parametrize("field,expected", [
    ("process.file.path", None),
    ("process.file.hashes.value", OcsfPath((("process", "file", "hashes"),), ("value",), ())),
    ("evidences.file.hashes.value", OcsfPath((("evidences",), ("file", "hashes")), ("value",), ())),
    ("x_forwarded_for", OcsfPath((("x_forwarded_for",),), (), ())),
    ("unmapped.objectRef.namespace", OcsfPath((), ("unmapped",), ("objectRef", "namespace"))),
    ("resources.data.tag", OcsfPath((("resources",),), ("data",), ("tag",))),
])
def test_split_ocsf_path(field, expected):
    assert split_ocsf_path(field) == expected


def test_array_fields_use_exists(ocsf_backend):
    assert ocsf_backend.convert(_rule("""
            sel:
                process.file.hashes.value: abc
                evidences.file.hashes.value|startswith: de
                x_forwarded_for: 1.2.3.4
    """)) == [
        "exists(process.file.hashes, x0 -> lower(x0.value) = lower('abc')) AND "
        "exists(evidences, x0 -> exists(x0.file.hashes, x1 -> startswith(lower(x1.value), lower('de')))) AND "
        "exists(x_forwarded_for, x0 -> lower(x0) = lower('1.2.3.4'))"
    ]


def test_array_field_not_matches_no_element(ocsf_backend):
    assert ocsf_backend.convert(_rule("""
            sel:
                process.file.hashes.value: abc
    """, "not sel")) == ["NOT exists(process.file.hashes, x0 -> lower(x0.value) = lower('abc'))"]


def test_free_form_fields_use_json_paths(ocsf_backend):
    assert ocsf_backend.convert(_rule("""
            sel:
                unmapped.Initiated: 'true'
                unmapped.objectRef.namespace|contains: kube
                unmapped.SourcePort: 445
                unmapped.Port|gt: 1024
                unmapped.Flag: true
                unmapped.weird key: x
                api.request.data.userName|exists: true
                resources.data.tag: prod
    """)) == [
        "lower(unmapped:Initiated::string) = lower('true') AND "
        "contains(lower(unmapped:objectRef.namespace::string), lower('kube')) AND "
        "try_cast(unmapped:SourcePort AS DOUBLE) = 445 AND "
        "try_cast(unmapped:Port AS DOUBLE) > 1024 AND "
        "try_cast(unmapped:Flag AS BOOLEAN) = true AND "
        "lower(unmapped:['weird key']::string) = lower('x') AND "
        "api.request.data:userName is not null AND "
        "exists(resources, x0 -> lower(x0.data:tag::string) = lower('prod'))"
    ]


def test_or_regex_optimization_on_array_field(ocsf_backend):
    assert ocsf_backend.convert(_rule("""
            sel:
                answers.rdata|endswith: ['.ru', '.cn', '.su']
    """)) == ["exists(answers, x0 -> x0.rdata rlike '(?iu)(\\\\.ru|\\\\.cn|\\\\.su)$')"]


def test_keywords_use_raw_data(ocsf_backend):
    assert ocsf_backend.convert(_rule("""
            sel:
                - mimikatz
    """)) == ["contains(lower(raw_data), lower('mimikatz'))"]


def test_explicit_raw_log_field_wins(ocsf_backend):
    backend = DatabricksBackend(ocsf=True, raw_log_field="message")
    assert backend.convert(_rule("""
            sel:
                - mimikatz
    """)) == ["contains(lower(message), lower('mimikatz'))"]


def test_disabled_by_default_without_ocsf_pipeline():
    assert DatabricksBackend().convert(_rule("""
            sel:
                process.file.hashes.value: abc
                unmapped.Initiated: 'true'
            kw:
                - evil
    """, "sel and kw")) == [
        "lower(process.file.hashes.value) = lower('abc') AND lower(unmapped.Initiated) = lower('true') "
        "AND contains(lower(raw), lower('evil'))"
    ]


def test_option_false_disables_for_ocsf_pipeline():
    backend = DatabricksBackend(ocsf_pipeline(), ocsf="false")
    query = backend.convert(SigmaCollection.from_yaml("""
        title: Test
        logsource: {category: antivirus}
        detection:
            sel: {Filename: test.exe}
            condition: sel
    """))[0]
    assert "exists(" not in query


def test_auto_enabled_for_ocsf_pipeline():
    query = DatabricksBackend(ocsf_pipeline()).convert(SigmaCollection.from_yaml("""
        title: Test
        logsource: {category: antivirus}
        detection:
            sel: {Filename|endswith: .exe}
            kw: [evil]
            condition: sel or kw
    """))[0]
    assert "exists(evidences, x0 -> endswith(lower(x0.file.name), lower('.exe')))" in query
    assert "contains(lower(raw_data), lower('evil'))" in query


def test_auto_enabled_for_lakewatch_format():
    backend = DatabricksBackend(table_name="t")
    rule = _rule("""
            sel:
                process.file.hashes.value: abc
    """).rules[0]
    sql = json.loads(backend.convert_rule(rule, "lakewatch")[0])["sql"]
    assert "exists(process.file.hashes, x0 -> lower(x0.value) = lower('abc'))" in sql


def test_invalid_option_value():
    with pytest.raises(ValueError, match="ocsf"):
        DatabricksBackend(ocsf="maybe")
