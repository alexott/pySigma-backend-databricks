"""Pruning of unsupported fields at the condition root (Lakewatch parsed mode)."""

import json
import warnings

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError, SigmaTransformationError

from sigma.backends.databricks import DatabricksBackend

CB = "carbonblack_endpoint_event"
SEC_PROC = "windows_security_process"

LOGSOURCE = "    product: windows\n    category: process_creation"

CERTUTIL = """
    selection_img:
        - Image|endswith: '\\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_flags:
        CommandLine|contains:
            - 'urlcache'
            - 'verifyctl'
    condition: all of selection_*
"""

ADFIND = """
    selection_1:
        CommandLine|contains: 'objectcategory'
    selection_2:
        CommandLine|contains: 'trustdmp'
    selection_3:
        OriginalFileName: 'AdFind.exe'
    filter:
        Image|endswith: '\\adfind.exe'
    condition: 1 of selection* and not filter
"""

BOINC = """
    selection:
        OriginalFileName: 'boinc.exe'
    filter:
        Image|endswith: '\\boinc.exe'
    condition: selection and not filter
"""

IN_FILTER = """
    selection:
        CommandLine|contains: 'x'
    filter:
        OriginalFileName: 'a.exe'
    condition: selection and not filter
"""


def _rule(detection, logsource=LOGSOURCE):
    return SigmaCollection.from_yaml(
        f"title: T\nstatus: test\nlogsource:\n{logsource}\ndetection:{detection}"
    ).rules[0]


def _sql(parser, detection, **opts):
    backend = DatabricksBackend(
        parsers=parser, table_name="t", catalog_name="c", schema_name="s", warehouse_id="w", **opts
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        queries = backend.convert_rule(_rule(detection), "lakewatch")
    assert len(queries) == 1
    return json.loads(queries[0])["sql"]


def test_certutil_pruned_cb():
    sql = _sql(CB, CERTUTIL)
    assert "originalfilename" not in sql.lower()
    assert "certutil.exe" in sql
    assert "urlcache" in sql and "verifyctl" in sql
    assert "endswith(lower(childproc_name), '\\\\certutil.exe')" in sql
    assert "(contains(lower(target_cmdline), 'urlcache') OR contains(lower(target_cmdline), 'verifyctl'))" in sql


def test_renamed_adfind_pruned_cb():
    sql = _sql(CB, ADFIND)
    assert "originalfilename" not in sql.lower()
    assert "NOT" in sql
    assert "adfind.exe" in sql
    assert "objectcategory" in sql and "trustdmp" in sql


def test_renamed_boinc_fails_empty():
    with pytest.raises(SigmaError) as exc:
        _sql(CB, BOINC)
    assert str(exc.value).startswith(
        "field OriginalFileName is not supported by profile carbonblack_endpoint_event "
        "(nothing is left once it's dropped)"
    )


def test_unsupported_in_filter_fails_negation():
    with pytest.raises(SigmaError) as exc:
        _sql(CB, IN_FILTER)
    assert (
        "field OriginalFileName is not supported by profile carbonblack_endpoint_event "
        "(it is under a negation, so it can't be dropped)"
    ) in str(exc.value)


def test_option_off_keeps_old_error():
    with pytest.raises(SigmaTransformationError, match="field OriginalFileName is not supported by profile "
                       "carbonblack_endpoint_event"):
        _sql(CB, CERTUTIL, prune_unsupported=False)


def test_option_string_false():
    with pytest.raises(SigmaTransformationError, match="field OriginalFileName is not supported"):
        _sql(CB, CERTUTIL, prune_unsupported="false")
    assert DatabricksBackend(prune_unsupported="false").prune_unsupported is False
    assert DatabricksBackend().prune_unsupported is True


def test_security_4688_pruned():
    sql = _sql(SEC_PROC, CERTUTIL)
    assert "originalfilename" not in sql.lower()
    assert "urlcache" in sql
