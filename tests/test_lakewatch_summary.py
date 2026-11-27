"""Tests for the default summary, the sigma_entity column and output-expression resolution."""

import dataclasses
import json
import warnings
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaConversionError
from sigma.types import SigmaString

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.lakewatch_output import PLACEHOLDER_IDENTIFIER, escape_title, placeholders

PROFILES_DIR = Path(__file__).parent.parent / "sigma" / "pipelines" / "databricks" / "lakewatch" / "profiles"

SYSMON = "windows_sysmon_process"
CS = "crowdstrike_fdr_event"
CT = "aws_cloudtrail"

DETECTION = {
    SYSMON: ("windows", "process_creation", "Image|endswith: '\\powershell.exe'"),
    CS: ("windows", "process_creation", "Image|endswith: '\\rundll32.exe'"),
    CT: ("aws", "service: cloudtrail", "eventName: ConsoleLogin"),
}


def _rule(parser, title="Encoded PowerShell"):
    product, category, cond = DETECTION[parser]
    category = category if category.startswith("service") else f"category: {category}"
    return SigmaCollection.from_yaml(
        f"""
title: {json.dumps(title)}
status: test
logsource:
    product: {product}
    {category}
detection:
    sel:
        {cond}
    condition: sel
"""
    ).rules[0]


def _backend(parser, **options):
    return DatabricksBackend(parsers=parser, table_name="t", catalog_name="c", schema_name="s",
                           warehouse_id="w", **options)


def _convert(parser, title="Encoded PowerShell", **options):
    backend = _backend(parser, **options)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        queries = backend.convert_rule(_rule(parser, title), "lakewatch")
    assert len(queries) == 1
    return json.loads(queries[0])


def _resolver_for(parser, product, service_line):
    """Return a backend set up for a rule of the given logsource."""
    backend = _backend(parser)
    rule = SigmaCollection.from_yaml(
        f"""
title: T
status: test
logsource:
    product: {product}
    {service_line}
detection:
    sel:
        EventID: 1
    condition: sel
"""
    ).rules[0]
    backend._parsed_setup()
    profile, schema, table = next(s for s in backend._selected if s[0].profile == parser)
    backend._current_profile = (profile, schema, table)
    backend._current_block = profile.block_for(rule.logsource)
    backend._current_rule = rule
    return backend


def _resolver(parser):
    """Return a backend set up as during the conversion of a rule for ``parser``."""
    backend = _backend(parser)
    rule = _rule(parser)
    backend._parsed_setup()
    profile, schema, table = next(s for s in backend._selected if s[0].profile == parser)
    backend._current_profile = (profile, schema, table)
    backend._current_block = profile.block_for(rule.logsource)
    backend._current_rule = rule
    return backend


def test_default_summary_uses_entity():
    out = _convert(SYSMON)
    assert out["doc"]["output"]["summary"] == "Encoded PowerShell on {sigma_entity}"
    assert out["sql"].startswith("SELECT *, Computer AS sigma_entity\nFROM ")
    assert out["doc"]["output"]["default_context"] is True


def test_entity_sql_expression():
    out = _convert(CS)
    assert out["sql"].startswith("SELECT *, coalesce(nullif(ComputerName, ''), aid) AS sigma_entity\nFROM ")


def test_entity_variant_path():
    out = _convert(CT)
    assert out["sql"].startswith(
        "SELECT *, try_variant_get(userIdentity, '$.arn', 'string') AS sigma_entity\nFROM "
    )


def test_title_only_summary_warns(tmp_path):
    text = (PROFILES_DIR / f"{SYSMON}.yml").read_text()
    text = "\n".join(line for line in text.splitlines() if not line.startswith("entity:"))
    (tmp_path / f"{SYSMON}.yml").write_text(text)
    backend = _backend(SYSMON, lakewatch_profiles_dir=str(tmp_path))
    with pytest.warns(UserWarning, match="has no entity: all signals of this rule group into one alert"):
        queries = backend.convert_rule(_rule(SYSMON), "lakewatch")
    out = json.loads(queries[0])
    assert out["doc"]["output"]["summary"] == "Encoded PowerShell"
    assert out["sql"].startswith("SELECT *\nFROM ")


def test_title_braces_escaped_in_summary():
    out = _convert(SYSMON, title="Suspicious {random} Name")
    assert out["doc"]["output"]["summary"] == "Suspicious (random) Name on {sigma_entity}"


def test_ocsf_summary_unchanged():
    backend = DatabricksBackend(table_name="t", catalog_name="c", schema_name="s", warehouse_id="w", ocsf=True)
    rule = SigmaCollection.from_yaml(
        """
title: Plain Title
status: test
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        Image|endswith: '\\powershell.exe'
    condition: sel
"""
    ).rules[0]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        out = json.loads(backend.convert_rule(rule, "lakewatch")[0])
    assert out["doc"]["output"]["summary"] == "Plain Title"
    assert out["sql"].startswith("SELECT *\nFROM")


def test_check_placeholders():
    backend = _resolver(SYSMON)
    cols = backend._output_columns(["Extra"])
    assert {"sigma_entity", "extra", "computer"} <= cols
    backend._check_placeholders("a {sigma_entity} {EXTRA} {computer}", cols)
    with pytest.raises(SigmaConversionError, match=r"placeholder \{nope\} is not an output column of profile "
                                                  r"windows_sysmon_process; add it under select"):
        backend._check_placeholders("x {nope}", cols)
    with pytest.raises(SigmaConversionError, match="placeholder"):
        backend._check_placeholders("x {a.b}", cols)


def test_select_list_aliases():
    backend = _resolver(SYSMON)
    assert backend._select_list({"cmd": "CommandLine"}).startswith("*, Computer AS sigma_entity, ")
    for alias in ("sigma_entity", "Computer", "bad alias"):
        with pytest.raises(SigmaConversionError, match=f"select alias {alias} clashes with an output column"):
            backend._select_list({alias: "x"})


def test_resolve_output_expr_sigma_field():
    backend = _resolver(SYSMON)
    expr = backend._resolve_output_expr("CommandLine")
    profile, _, _ = backend._current_profile
    target = profile.mappings_for(backend._current_block)["CommandLine"].targets[0]
    assert target == "EventData[CommandLine]"
    path = backend._resolve_parsed_field(target)
    assert expr == backend._render_path(path, SigmaString(""))[1]
    assert expr != target


def test_resolve_output_expr_unknown_identifier_fails():
    backend = _resolver(SYSMON)
    with pytest.raises(SigmaConversionError, match="NoSuchField"):
        backend._resolve_output_expr("NoSuchField")


def test_resolve_output_expr_transform_mapping_fails():
    backend = _resolver(CS)
    with pytest.raises(SigmaConversionError, match="transform"):
        backend._resolve_output_expr("Image")


def test_resolve_output_expr_sql_verbatim():
    backend = _resolver(SYSMON)
    assert backend._resolve_output_expr("lower(Computer)") == "lower(Computer)"


def test_resolve_output_expr_schema_path():
    backend = _resolver(CT)
    assert backend._resolve_output_expr("userIdentity.arn") == "try_variant_get(userIdentity, '$.arn', 'string')"


def test_output_helpers():
    assert escape_title("a {b} c") == "a (b) c"
    assert placeholders("x {a} y { b } {c}") == ["a", "b", "c"]
    assert PLACEHOLDER_IDENTIFIER.match("abc_1")
    assert not PLACEHOLDER_IDENTIFIER.match("a.b")


def test_select_alias_sigma_entity_clashes_without_entity():
    backend = _resolver(SYSMON)
    profile, schema, table = backend._current_profile
    backend._current_profile = (dataclasses.replace(profile, entity=None), schema, table)
    with pytest.raises(
        SigmaConversionError,
        match=f"select alias sigma_entity clashes with an output column of profile {SYSMON}",
    ):
        backend._select_list({"sigma_entity": "Computer"})


def test_resolve_output_expr_case_sensitive_without_any():
    backend = _resolver(CS)
    with pytest.raises(SigmaConversionError, match=rf"commandline.*profile {CS}"):
        backend._resolve_output_expr("commandline")


def test_resolve_output_expr_case_insensitive_with_any():
    backend = _resolver_for("windows_application", "windows", "service: application")
    assert backend._current_block.event_data == "any"
    assert backend._resolve_output_expr("computer") == backend._resolve_output_expr("Computer")


@pytest.mark.parametrize("template", ["x {sigma_entity", "x } y", "{{sigma_entity}}"])
def test_unbalanced_braces_rejected(template):
    backend = _resolver(SYSMON)
    cols = backend._output_columns([])
    with pytest.raises(SigmaConversionError, match=f"unbalanced braces in summary of profile {SYSMON}"):
        backend._check_placeholders(template, cols)
    with pytest.raises(SigmaConversionError,
                       match=f"unbalanced braces in context value of profile {SYSMON}"):
        backend._check_placeholders(template, cols, "context value")


def test_select_alias_is_quoted():
    backend = _resolver(SYSMON)
    assert backend._select_list({"from": "CommandLine"}).endswith(" AS `from`")
    assert "Computer AS sigma_entity" in backend._select_list({})
