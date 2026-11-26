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


@pytest.mark.parametrize("parser, col", [(ZSCALER, "url"), (UMBRELLA, "url")])
@pytest.mark.parametrize("field", ["c-uri", "cs-uri"])
def test_u2_converts_proxy(parser, col, field):
    sql = _sql(parser, "proxy", f"    sel:\n        {field}|contains: /a\n    condition: sel")
    assert f"AND (contains(lower({col}), lower('/a')))" in sql
    all_ = _sql(
        parser,
        "proxy",
        f"    sel:\n        {field}|contains|all:\n            - /a\n            - /b\n    condition: sel",
    )
    assert f"AND (contains(lower({col}), lower('/a')) AND contains(lower({col}), lower('/b')))" in all_
    end = _sql(parser, "proxy", f"    sel:\n        {field}|endswith: .hta\n    condition: sel")
    assert f"AND (endswith(lower({col}), lower('.hta')))" in end
    rx = _sql(parser, "proxy", f"    sel:\n        {field}|re: 'a.+b'\n    condition: sel")
    assert f"AND ({col} rlike 'a.+b')" in rx


@pytest.mark.parametrize("parser", [ZSCALER, UMBRELLA])
@pytest.mark.parametrize("field", ["c-uri", "cs-uri"])
@pytest.mark.parametrize(
    "detection, modifier",
    [
        ("{f}: /x", "eq"),
        ("{f}|startswith: /x", "startswith"),
        ("{f}: '*foo*'", "eq"),
    ],
)
def test_u2_rejects_proxy(parser, field, detection, modifier):
    det = "    sel:\n        " + detection.format(f=field) + "\n    condition: sel"
    msg = _convert_error(parser, "proxy", det)
    assert msg == f"field {field}: modifier {modifier} is not supported (profile {parser})"


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


@pytest.mark.parametrize(
    "parser, field",
    [(p, f) for p in (CLOUDFLARE, GCPLB) for f in ("cs-username", "cs-content-type")]
    + [(AKAMAI, f) for f in ("cs-user-agent", "cs-referer", "cs-username", "cs-content-type")]
    + [(AWSWAF, f) for f in ("sc-status", "cs-username", "cs-content-type")]
    + [(p, f) for p in (ZSCALER, UMBRELLA) for f in ("c-uri-query", "cs-uri-stem", "c-uri-extension", "cs-cookie")],
)
def test_unmapped(parser, field):
    category = "proxy" if parser in (ZSCALER, UMBRELLA) else "webserver"
    assert f"is not mapped by profile {parser}" in _convert_error(parser, category, _sel(field))


@pytest.mark.parametrize("field", ["cs-uri-stem", "cs-host"])
def test_gcplb_unmapped(field):
    assert f"is not mapped by profile {GCPLB}" in _convert_error(GCPLB, "webserver", _sel(field))


def test_entities():
    assert "ClientIP AS sigma_entity" in _sql(CLOUDFLARE, "webserver", _sel("cs-method"))
    assert "try_variant_get(httpRequest, '$.remoteIp', 'string') AS sigma_entity" in _sql(
        GCPLB, "webserver", _sel("cs-method")
    )
    assert "attackData.clientIP AS sigma_entity" in _sql(AKAMAI, "webserver", _sel("cs-method"))
    assert "try_variant_get(httpRequest, '$.clientIp', 'string') AS sigma_entity" in _sql(
        AWSWAF, "webserver", _sel("cs-method")
    )
    assert "user AS sigma_entity" in _sql(ZSCALER, "proxy", _sel("cs-method"))
    assert "identity AS sigma_entity" in _sql(UMBRELLA, "proxy", _sel("cs-method"))


def test_routing():
    def convertible(category):
        rules = DatabricksBackend().discover_parsers(SigmaCollection([_rule(category, _sel("cs-method"))]))["rules"]
        return rules[0]["convertible"]

    assert convertible("webserver") == sorted([CLOUDFLARE, GCPLB, AKAMAI, AWSWAF])
    assert convertible("proxy") == sorted([ZSCALER, UMBRELLA])


# --- akamai_waf and aws_waf_web_acl (split path and query: U1) --------------------------------

AK_PATH, AK_QUERY = "httpMessage.path", "httpMessage.query"
AW_URI = "try_variant_get(httpRequest, '$.uri', 'string')"
AW_ARGS = "try_variant_get(httpRequest, '$.args', 'string')"
AK_JOIN = f"concat_ws('?', nullif({AK_PATH}, ''), nullif({AK_QUERY}, ''))"
AW_JOIN = f"concat_ws('?', nullif({AW_URI}, ''), nullif({AW_ARGS}, ''))"


@pytest.mark.parametrize(
    "field, expected",
    [
        ("cs-uri-query", f"lower({AK_JOIN}) = lower('x')"),
        ("cs-uri-stem", f"lower({AK_PATH}) = lower('x')"),
        ("cs-method", "lower(httpMessage.method) = lower('x')"),
        ("cs-host", "lower(httpMessage.host) = lower('x')"),
    ],
)
def test_akamai_aliases(field, expected):
    assert f"AND ({expected})" in _sql(AKAMAI, "webserver", _sel(field))


def test_akamai_sc_status():
    # httpMessage.status is a STRING column, so the number renders as a (case-folded) string comparison.
    sql = _sql(AKAMAI, "webserver", "    sel:\n        sc-status: 200\n    condition: sel")
    assert "AND (lower(httpMessage.status) = lower('200'))" in sql


@pytest.mark.parametrize(
    "field, expected",
    [
        ("cs-uri-query", f"lower({AW_JOIN}) = lower('x')"),
        ("cs-uri-stem", f"lower({AW_URI}) = lower('x')"),
        (
            "cs-method",
            "lower(try_variant_get(httpRequest, '$.httpMethod', 'string')) = lower('x')",
        ),
    ],
)
def test_awswaf_aliases(field, expected):
    assert f"AND ({expected})" in _sql(AWSWAF, "webserver", _sel(field))


U1_CONTAINS = "    sel:\n        cs-uri-query|contains: x\n    condition: sel"


def test_u1_join_contains():
    assert f"AND (contains(lower({AK_JOIN}), lower('x')))" in _sql(AKAMAI, "webserver", U1_CONTAINS)
    assert f"AND (contains(lower({AW_JOIN}), lower('x')))" in _sql(AWSWAF, "webserver", U1_CONTAINS)


def test_u1_contains_all_converts():
    det = "    sel:\n        cs-uri-query|contains|all:\n            - /a\n            - /b\n    condition: sel"
    sql = _sql(AKAMAI, "webserver", det)
    assert (
        f"AND (contains(lower({AK_JOIN}), lower('/a')) AND contains(lower({AK_JOIN}), lower('/b')))"
    ) in sql


@pytest.mark.parametrize("parser, join", [(AKAMAI, AK_JOIN), (AWSWAF, AW_JOIN)])
def test_u1_literal_question_mark(parser, join):
    # \? is a literal ?, so the value is an exact comparison against the joined URI
    sql = _sql(parser, "webserver", "    sel:\n        cs-uri-query: '/a\\?b=1'\n    condition: sel")
    assert f"AND (lower({join}) = lower('/a?b=1'))" in sql


@pytest.mark.parametrize("parser, join", [(AKAMAI, AK_JOIN), (AWSWAF, AW_JOIN)])
def test_u1_corpus_value_converts(parser, join):
    # an unescaped ? is a single-character wildcard, so the value renders as an rlike
    det = (
        "    sel:\n        cs-uri-query: '/OA_HTML/BneViewerXMLService?bne:uueupload=TRUE'\n"
        "    condition: sel"
    )
    assert (
        f"AND ({join} rlike '(?isu)^/OA_HTML/BneViewerXMLService.bne:uueupload=TRUE$')"
    ) in _sql(parser, "webserver", det)


@pytest.mark.parametrize("parser, join", [(AKAMAI, AK_JOIN), (AWSWAF, AW_JOIN)])
def test_u1_contains_literal_question_mark(parser, join):
    det = "    sel:\n        cs-uri-query|contains: 'a\\?b'\n    condition: sel"
    assert f"AND (contains(lower({join}), lower('a?b')))" in _sql(parser, "webserver", det)


@pytest.mark.parametrize("parser", [AKAMAI, AWSWAF])
def test_u1_null_fails(parser):
    assert _convert_error(parser, "webserver", "    sel:\n        cs-uri-query: null\n    condition: sel")


@pytest.mark.parametrize("parser", [AKAMAI, AWSWAF])
@pytest.mark.parametrize("value", ["/login/index.php", "login="])
@pytest.mark.parametrize("mod", ["contains", "contains|all", "endswith"])
def test_u1_converts(parser, value, mod):
    _sql(parser, "webserver", f"    sel:\n        cs-uri-query|{mod}: '{value}'\n    condition: sel")


@pytest.mark.parametrize("field", ["labels.name", "requestHeadersInserted.name"])
def test_awswaf_array_variant_members_unmapped(field):
    assert f"is not mapped by profile {AWSWAF}" in _convert_error(AWSWAF, "webserver", _sel(field))


def test_awswaf_labels_whole_value():
    ok = _sql(AWSWAF, "webserver", "    sel:\n        labels|contains: x\n    condition: sel")
    assert "AND (contains(lower(to_json(labels)), lower('x')))" in ok
    err = _convert_error(AWSWAF, "webserver", _sel("labels"))
    assert err == (
        f"comparison against the whole VARIANT column labels supports only contains (profile {AWSWAF}) (rule 'T')"
    )


AW_HEADER = (
    "lower(try_variant_get(try_element_at(filter(try_variant_get(httpRequest, '$.headers', 'ARRAY<VARIANT>'), "
    "e -> lower(try_variant_get(e, '$.name', 'STRING')) = lower('{h}')), 1), '$.value', 'STRING')) = lower('x')"
)


@pytest.mark.parametrize(
    "field, header",
    [("cs-user-agent", "User-Agent"), ("cs-referer", "Referer"), ("cs-host", "Host")],
)
def test_aws_waf_headers(field, header):
    assert f"AND ({AW_HEADER.format(h=header)})" in _sql(AWSWAF, "webserver", _sel(field))


def test_aws_waf_header_array_identity():
    sql = _sql(AWSWAF, "webserver", _sel("httpRequest.headers.name", "host"))
    assert (
        "AND (exists(try_variant_get(httpRequest, '$.headers', 'ARRAY<VARIANT>'), "
        "x0 -> lower(try_variant_get(x0, '$.name', 'string')) = lower('host')))"
    ) in sql


def test_aws_waf_rule_match_array_identity():
    sql = _sql(AWSWAF, "webserver", _sel("ruleGroupList.terminatingRule.ruleMatchDetails.conditionType"))
    assert (
        "AND (exists(ruleGroupList, x0 -> exists("
        "try_variant_get(x0, '$.terminatingRule.ruleMatchDetails', 'ARRAY<VARIANT>'), "
        "x1 -> lower(try_variant_get(x1, '$.conditionType', 'string')) = lower('x'))))"
    ) in sql


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


def test_akamai_snapshot():
    assert _sql(AKAMAI, "webserver", SNAP) == (
        "SELECT *, attackData.clientIP AS sigma_entity\n"
        "FROM t\n"
        "WHERE IN_TIMERANGE(time)\n"
        "  AND (lower(httpMessage.method) = lower('POST') "
        f"AND contains(lower({AK_JOIN}), lower('/owa/auth/')) "
        "AND lower(httpMessage.status) = lower('200'))"
    )


def test_awswaf_snapshot():
    det = "    sel:\n        cs-method: POST\n        cs-uri-query|contains: /owa/auth/\n    condition: sel"
    assert _sql(AWSWAF, "webserver", det) == (
        "SELECT *, try_variant_get(httpRequest, '$.clientIp', 'string') AS sigma_entity\n"
        "FROM t\n"
        "WHERE IN_TIMERANGE(time)\n"
        "  AND (lower(try_variant_get(httpRequest, '$.httpMethod', 'string')) = lower('POST') "
        f"AND contains(lower({AW_JOIN}), lower('/owa/auth/')))"
    )


# --- zscaler_zia_web_log and ciscoumbrella_proxy (proxy; whole-URL U2) -------------------------


@pytest.mark.parametrize("field", ["c-uri", "cs-uri"])
@pytest.mark.parametrize("parser", [ZSCALER, UMBRELLA])
def test_proxy_url_alias_is_u2(parser, field):
    # The URL alias is the whole-URL column, so only U2 modifiers convert (see test_u2_*_proxy).
    sql = _sql(parser, "proxy", f"    sel:\n        {field}|contains: x\n    condition: sel")
    assert "AND (contains(lower(url), lower('x')))" in sql


@pytest.mark.parametrize(
    "field, expected",
    [
        ("c-useragent", "lower(useragent) = lower('x')"),
        ("cs-method", "lower(requestmethod) = lower('x')"),
        ("cs-host", "lower(hostname) = lower('x')"),
        ("dst_ip", "lower(serverip) = lower('x')"),
    ],
)
def test_zscaler_aliases(field, expected):
    assert f"AND ({expected})" in _sql(ZSCALER, "proxy", _sel(field))


@pytest.mark.parametrize(
    "field, expected",
    [
        ("c-useragent", "lower(userAgent) = lower('x')"),
        ("cs-method", "lower(requestMethod) = lower('x')"),
        ("cs-host", "lower(hostName) = lower('x')"),
        ("dst_ip", "lower(destinationIp) = lower('x')"),
    ],
)
def test_umbrella_aliases(field, expected):
    assert f"AND ({expected})" in _sql(UMBRELLA, "proxy", _sel(field))


def test_proxy_sc_status():
    det = "    sel:\n        sc-status: 200\n    condition: sel"
    # Zscaler status is a STRING column; Umbrella statusCode is INT.
    assert "AND (lower(status) = lower('200'))" in _sql(ZSCALER, "proxy", det)
    assert "AND (statusCode = 200)" in _sql(UMBRELLA, "proxy", det)


PROXY_SNAP = (
    "    sel:\n        c-uri|endswith: .hta\n        cs-method: GET\n        c-useragent|contains: curl\n"
    "    condition: sel"
)


def test_zscaler_snapshot():
    assert _sql(ZSCALER, "proxy", PROXY_SNAP) == (
        "SELECT *, user AS sigma_entity\n"
        "FROM t\n"
        "WHERE IN_TIMERANGE(time)\n"
        "  AND (endswith(lower(url), lower('.hta')) "
        "AND lower(requestmethod) = lower('GET') "
        "AND contains(lower(useragent), lower('curl')))"
    )


def test_umbrella_snapshot():
    assert _sql(UMBRELLA, "proxy", PROXY_SNAP) == (
        "SELECT *, identity AS sigma_entity\n"
        "FROM t\n"
        "WHERE IN_TIMERANGE(time)\n"
        "  AND (endswith(lower(url), lower('.hta')) "
        "AND lower(requestMethod) = lower('GET') "
        "AND contains(lower(userAgent), lower('curl')))"
    )
