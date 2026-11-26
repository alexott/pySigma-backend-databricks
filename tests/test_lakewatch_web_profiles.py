"""Tests for the built-in web Lakewatch profiles (webserver and proxy categories)."""

import json
import warnings

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.databricks import LakewatchConversionError


def _rule(category, detection):
    return SigmaCollection.from_yaml(
        f"""
title: T
status: test
logsource:
    category: {category}
detection:
{detection}
"""
    ).rules[0]


def _convert(parser, category, detection):
    backend = DatabricksBackend(parsers=parser, table_name="t", catalog_name="c", schema_name="s")
    queries = backend.convert_rule(_rule(category, detection), "lakewatch")
    assert len(queries) == 1
    return json.loads(queries[0])["sql"]


def _sql(parser, category, detection):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return _convert(parser, category, detection)


def _convert_error(parser, category, detection):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with pytest.raises((SigmaTransformationError, LakewatchConversionError)) as exc:
            _convert(parser, category, detection)
    return str(exc.value)


def _sel(field, value="x"):
    return f"    sel:\n        {field}: '{value}'\n    condition: sel"


CLOUDFLARE = "cloudflare_http_request"
GCPLB = "gcp_http_load_balancer"
AKAMAI = "akamai_waf"
AWSWAF = "aws_waf_web_acl"
ZSCALER = "zscaler_zia_web_log"
UMBRELLA = "ciscoumbrella_proxy"

LB_URL = "lower(try_variant_get(httpRequest, '$.requestUrl', 'string'))"

# --- cloudflare_http_request ----------------------------------------------------------------


@pytest.mark.parametrize(
    "field, expected",
    [
        ("cs-uri-query", "lower(ClientRequestURI) = lower('x')"),
        ("cs-uri-stem", "lower(ClientRequestPath) = lower('x')"),
        ("cs-method", "lower(ClientRequestMethod) = lower('x')"),
        ("cs-user-agent", "lower(ClientRequestUserAgent) = lower('x')"),
        ("cs-referer", "lower(ClientRequestReferer) = lower('x')"),
        ("cs-host", "lower(ClientRequestHost) = lower('x')"),
    ],
)
def test_cloudflare_aliases(field, expected):
    assert f"AND ({expected})" in _sql(CLOUDFLARE, "webserver", _sel(field))


def test_cloudflare_sc_status():
    sql = _sql(CLOUDFLARE, "webserver", "    sel:\n        sc-status: 200\n    condition: sel")
    assert "AND (EdgeResponseStatus = 200)" in sql


def test_cloudflare_u2_not_applied():
    # Cloudflare ClientRequestURI is path plus query, so plain equality stays allowed.
    assert "lower(ClientRequestURI) = lower('/a')" in _sql(CLOUDFLARE, "webserver", _sel("cs-uri-query", "/a"))


# --- gcp_http_load_balancer -----------------------------------------------------------------


@pytest.mark.parametrize(
    "field, expected",
    [
        ("cs-method", "lower(try_variant_get(httpRequest, '$.requestMethod', 'string')) = lower('x')"),
        ("cs-user-agent", "lower(try_variant_get(httpRequest, '$.userAgent', 'string')) = lower('x')"),
        ("cs-referer", "lower(try_variant_get(httpRequest, '$.referer', 'string')) = lower('x')"),
    ],
)
def test_gcplb_aliases(field, expected):
    assert f"AND ({expected})" in _sql(GCPLB, "webserver", _sel(field))


def test_gcplb_sc_status():
    sql = _sql(GCPLB, "webserver", "    sel:\n        sc-status: 200\n    condition: sel")
    assert "AND (try_variant_get(httpRequest, '$.status', 'bigint') = 200)" in sql


def test_u2_converts():
    contains = "    sel:\n        cs-uri-query|contains: /owa/auth/\n    condition: sel"
    sql = _sql(GCPLB, "webserver", contains)
    assert f"AND (contains({LB_URL}, lower('/owa/auth/')))" in sql
    all_ = "    sel:\n        cs-uri-query|contains|all:\n            - /a\n            - /b\n    condition: sel"
    both = _sql(GCPLB, "webserver", all_)
    assert f"AND (contains({LB_URL}, lower('/a')) AND contains({LB_URL}, lower('/b')))" in both
    end = _sql(GCPLB, "webserver", "    sel:\n        cs-uri-query|endswith: .php\n    condition: sel")
    assert f"AND (endswith({LB_URL}, lower('.php')))" in end
    rx = _sql(GCPLB, "webserver", "    sel:\n        cs-uri-query|re: 'a.+b'\n    condition: sel")
    assert "AND (try_variant_get(httpRequest, '$.requestUrl', 'string') rlike 'a.+b')" in rx


@pytest.mark.parametrize(
    "detection, modifier",
    [
        (_sel("cs-uri-query", "/x"), "eq"),
        ("    sel:\n        cs-uri-query|startswith: /x\n    condition: sel", "startswith"),
        # A wildcard-only equality ('*foo*') is still plain equality (no modifier name), so U2 rejects it too.
        (_sel("cs-uri-query", "*foo*"), "eq"),
    ],
)
def test_u2_rejects(detection, modifier):
    msg = _convert_error(GCPLB, "webserver", detection)
    assert msg == f"field cs-uri-query: modifier {modifier} is not supported (profile {GCPLB})"


# --- unmapped / entities / routing ----------------------------------------------------------


@pytest.mark.parametrize("parser", [CLOUDFLARE, GCPLB])
@pytest.mark.parametrize("field", ["cs-username", "cs-content-type"])
def test_unmapped(parser, field):
    assert f"is not mapped by profile {parser}" in _convert_error(parser, "webserver", _sel(field))


@pytest.mark.parametrize("field", ["cs-uri-stem", "cs-host"])
def test_gcplb_unmapped(field):
    assert f"is not mapped by profile {GCPLB}" in _convert_error(GCPLB, "webserver", _sel(field))


def test_entities():
    assert "ClientIP AS sigma_entity" in _sql(CLOUDFLARE, "webserver", _sel("cs-method"))
    assert "try_variant_get(httpRequest, '$.remoteIp', 'string') AS sigma_entity" in _sql(
        GCPLB, "webserver", _sel("cs-method")
    )


def test_routing():
    web = json.dumps(
        DatabricksBackend().discover_parsers(SigmaCollection([_rule("webserver", _sel("cs-method"))])), default=str
    )
    assert CLOUDFLARE in web and GCPLB in web
    proxy = json.dumps(
        DatabricksBackend().discover_parsers(SigmaCollection([_rule("proxy", _sel("cs-method"))])), default=str
    )
    assert CLOUDFLARE not in proxy and GCPLB not in proxy


# --- snapshots ------------------------------------------------------------------------------

SNAP = (
    "    sel:\n        cs-method: POST\n        cs-uri-query|contains: /owa/auth/\n        sc-status: 200\n"
    "    condition: sel"
)


def test_cloudflare_snapshot():
    assert _sql(CLOUDFLARE, "webserver", SNAP) == (
        "SELECT *, ClientIP AS sigma_entity\n"
        "FROM t\n"
        "WHERE IN_TIMERANGE(time)\n"
        "  AND (lower(ClientRequestMethod) = lower('POST') "
        "AND contains(lower(ClientRequestURI), lower('/owa/auth/')) "
        "AND EdgeResponseStatus = 200)"
    )


def test_gcplb_snapshot():
    assert _sql(GCPLB, "webserver", SNAP) == (
        "SELECT *, try_variant_get(httpRequest, '$.remoteIp', 'string') AS sigma_entity\n"
        "FROM t\n"
        "WHERE IN_TIMERANGE(time)\n"
        "  AND (lower(try_variant_get(httpRequest, '$.requestMethod', 'string')) = lower('POST') "
        f"AND contains({LB_URL}, lower('/owa/auth/')) "
        "AND try_variant_get(httpRequest, '$.status', 'bigint') = 200)"
    )


def test_cloudflare_variant_columns():
    whole = _sql(CLOUDFLARE, "webserver", "    sel:\n        Cookies|contains: x\n    condition: sel")
    member = _sql(CLOUDFLARE, "webserver", _sel("RequestHeaders.User-Agent"))
    assert "AND (contains(lower(to_json(Cookies)), lower('x')))" in whole
    assert "AND (lower(try_variant_get(RequestHeaders, '$[\\'User-Agent\\']', 'string')) = lower('x'))" in member
