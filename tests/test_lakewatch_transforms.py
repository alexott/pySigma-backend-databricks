"""Tests for the Lakewatch profile value transforms."""

import json
import warnings

import pytest
from sigma.collection import SigmaCollection
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCompareExpression,
    SigmaExists,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from sigma.backends.databricks import DatabricksBackend
from sigma.backends.databricks.field_paths import first_set_field_name, join_field_name
from sigma.backends.databricks.schema_catalog import SchemaCatalog
from sigma.pipelines.databricks.lakewatch.profile import ProfileError, load_profiles, validate_profile
from sigma.pipelines.databricks.lakewatch.transforms import (
    TransformFailure,
    apply_chain,
    parse_transform,
)

T = ("t",)


def run(spec, value, targets=T, all_values=False):
    chain = parse_transform(spec, {})
    return apply_chain(chain, value, targets, field="F", all_values=all_values)


def one(spec, text, **kw):
    ((targets, value),) = run(spec, SigmaString(text) if isinstance(text, str) else text, **kw)
    return targets, value


def test_map_list_and_default():
    spec = {"map": {"values": {"tcp": 6, "both": [1, 2]}}}
    assert run(spec, SigmaString("TCP")) == [(T, SigmaNumber(6))]
    assert [v for _, v in run(spec, SigmaString("both"))] == [SigmaNumber(1), SigmaNumber(2)]
    with pytest.raises(TransformFailure, match="not in the map"):
        run(spec, SigmaString("udp"))
    keep = {"map": {"values": {"tcp": 6}, "default": "keep"}}
    assert str(one(keep, "udp")[1]) == "udp"
    assert run({"map": {"values": {"a": True, "b": "x"}}}, SigmaString("a"))[0][1] == SigmaBool(True)


def test_map_wildcard_fails_unless_keep():
    with pytest.raises(TransformFailure):
        run({"map": {"values": {"tcp": 6}}}, SigmaString("tc*"))
    assert str(one({"map": {"values": {"tcp": 6}, "default": "keep"}}, "tc*")[1]) == "tc*"


def test_case():
    assert str(one({"case": "upper"}, "abc")[1]) == "ABC"
    assert str(one({"case": "lower"}, "ABC")[1]) == "abc"


def test_basename_shapes():
    with pytest.warns(UserWarning, match="directory dropped"):
        assert str(one("basename", r"C:\x\cmd.exe")[1]) == "cmd.exe"
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert str(one("basename", r"*\cmd.exe")[1]) == "cmd.exe"
        assert str(one("basename", "*cmd.exe")[1]) == "*cmd.exe"
    with pytest.warns(UserWarning):
        assert str(one("basename", "/usr/bin/curl")[1]) == "curl"
    trailing = SigmaString("C:\\Windows\\") + SigmaString("*")
    with pytest.raises(TransformFailure, match="basename cannot express"):
        run("basename", trailing)
    with pytest.raises(TransformFailure, match="basename cannot express"):
        run("basename", SigmaString("C:\\Windows\\"))


def test_path_prefix_device():
    spec = {"path_prefix": {"rewrite": [{"from": "[A-Za-z]:", "to": r"\Device\HarddiskVolume*"}]}}
    value = one(spec, r"C:\Windows\x.exe")[1]
    assert str(value) == r"\Device\HarddiskVolume*\Windows\x.exe"
    assert value.contains_special()
    assert str(one(spec, r"*\x.exe")[1]) == r"*\x.exe"


def test_registry_path_kernel_hive():
    spec = {"registry_path": {"hive": "kernel"}}
    assert str(one(spec, r"HKLM\SOFTWARE\Run*")[1]) == r"\REGISTRY\MACHINE\SOFTWARE\Run*"
    value = one(spec, r"HKCU\Software\X")[1]
    assert str(value) == r"\REGISTRY\USER\*\Software\X"
    assert value.contains_special()
    assert str(one(spec, r"HKEY_CLASSES_ROOT\x")[1]) == r"\REGISTRY\MACHINE\SOFTWARE\Classes\x"
    assert str(one(spec, r"*\Run\*")[1]) == r"*\Run\*"
    assert str(one(spec, r"HKLMX\a")[1]) == r"HKLMX\a"
    assert str(one({"registry_path": {"hive": "short"}}, r"\REGISTRY\USER\S-1\x")[1]) == r"HKU\S-1\x"
    assert str(one({"registry_path": {"hive": "long"}}, "HKCR")[1]) == r"HKEY_LOCAL_MACHINE\SOFTWARE\Classes"


def test_registry_path_split_targets_join():
    spec = {"registry_path": {"hive": "short", "split": {"key": "event.RegObjectName", "value": "event.RegValueName"}}}
    (chain,) = [parse_transform(spec, {})]
    assert chain[0].supplies_targets
    assert chain[0].required_paths() == ("event.RegObjectName", "event.RegValueName")
    targets, _ = one(spec, r"HKLM\x")
    assert targets == (join_field_name("\\", ["event.RegObjectName", "event.RegValueName"]),)


HASHES = {"hashes": {"algos": {"MD5": "m", "SHA1": "s1", "SHA256": "s256"}}}


def test_hashes_prefixed_and_length():
    h = "AB" * 32
    assert one(HASHES, f"SHA256={h}") == (("s256",), SigmaString(h))
    assert one(HASHES, "a" * 32)[0] == ("m",)
    assert one(HASHES, "a" * 40)[0] == ("s1",)
    assert one(HASHES, f"*MD5={'c' * 32}*") == (("m",), SigmaString("c" * 32))
    with pytest.raises(TransformFailure):
        run(HASHES, SigmaString("abc"))


def test_hashes_all_missing_algo_fails():
    with pytest.raises(TransformFailure, match="IMPHASH is not available"):
        run(HASHES, SigmaString("IMPHASH=" + "a" * 32), all_values=True)
    with pytest.warns(UserWarning, match="IMPHASH"):
        assert run(HASHES, SigmaString("IMPHASH=" + "a" * 32)) == []


def test_domain_user():
    spec = {"domain_user": {"domain": "d", "user": "u"}}
    targets, value = one(spec, r"CORP\bob")
    assert targets == (join_field_name("\\", ["d", "u"]),)
    assert str(value) == r"CORP\bob"
    assert parse_transform(spec, {})[0].required_paths() == ("d", "u")


def test_to_hex():
    assert str(one("to_hex", SigmaNumber(4120))[1]) == "0x1018"
    assert str(one("to_hex", "255")[1]) == "0xff"
    assert str(one({"to_hex": {"prefix": ""}}, "255")[1]) == "ff"
    for bad in (
        SigmaString("12*"), SigmaNumber(-1), SigmaRegularExpression("1"), SigmaString("abc"),
        SigmaCompareExpression(SigmaNumber(1), CompareOperators.GT),
    ):
        with pytest.raises(TransformFailure, match="exact decimal number"):
            run("to_hex", bad)


def test_first_set_targets():
    cands = [{"domain": "d1", "user": "u1"}, {"domain": "d2", "user": "u2"}]
    spec = {"first_set": {"candidates": cands}}
    targets, value = one(spec, "x")
    assert targets == (first_set_field_name([("d1", "u1"), ("d2", "u2")], ["-"]),)
    assert str(value) == "x"
    assert parse_transform(spec, {})[0].required_paths() == ("d1", "u1", "d2", "u2")
    with pytest.raises(ValueError, match="must be last"):
        parse_transform([spec, "basename"], {})


def test_first_set_one_candidate_fails():
    with pytest.raises(ValueError, match="at least 2"):
        parse_transform({"first_set": {"candidates": ["a"]}}, {})


def test_regex_replace():
    spec = {"regex_replace": {"pattern": r"\.exe$", "replacement": ""}}
    assert str(one(spec, "a.exe")[1]) == "a"


def test_chain_supplies_targets_must_be_last():
    with pytest.raises(ValueError, match="must be last"):
        parse_transform([HASHES, "basename"], {})
    assert len(parse_transform(["basename", HASHES], {})) == 2


def test_named_and_errors():
    named = {"n": parse_transform({"case": "lower"}, {})}
    assert len(parse_transform(["n", "to_str"], named)) == 2
    for bad in ("nope", {"nope": 1}, {"case": "x"}, {"map": {}}, "map", {"basename": 1}, {"a": 1, "b": 2}):
        with pytest.raises(ValueError):
            parse_transform(bad, {})


def test_regex_value_rejected():
    with pytest.raises(TransformFailure, match="cannot be applied to SigmaRegularExpression"):
        run("basename", SigmaRegularExpression("x"))


def test_to_int_to_str():
    assert one("to_int", "42")[1] == SigmaNumber(42)
    assert one("to_int", SigmaNumber(7))[1] == SigmaNumber(7)
    for bad in ("4a", "4*", ""):
        with pytest.raises(TransformFailure):
            run("to_int", SigmaString(bad))
    assert str(one("to_str", SigmaNumber(5))[1]) == "5"
    assert str(one("to_str", SigmaBool(True))[1]) == "true"
    assert str(one("to_str", "x")[1]) == "x"
    assert SpecialChars.WILDCARD_MULTI in SigmaString("a*").s


def test_basename_keeps_directory_warning_unless_bare_wildcard():
    for text in (r"*\System32\cmd.exe", r"*System32\cmd.exe"):
        with pytest.warns(UserWarning, match="directory dropped"):
            assert str(one("basename", text)[1]) == "cmd.exe"


def test_basename_wildcard_in_file_name_warns():
    with pytest.warns(UserWarning, match="wildcard in the file name"):
        assert str(one("basename", r"*\py*.exe")[1]) == "py*.exe"
    with pytest.warns(UserWarning) as record:
        assert str(one("basename", r"C:\x\a*b.exe")[1]) == "a*b.exe"
    messages = [str(w.message) for w in record]
    assert any("wildcard in the file name" in m for m in messages)
    assert any("directory dropped" in m for m in messages)


def test_hashes_validate_prefixed_digests():
    for bad in ("MD5=", "MD5=abc", "SHA1=" + "a" * 32, "MD5=" + "g" * 32, "a" * 31 + "z"):
        with pytest.raises(TransformFailure):
            run(HASHES, SigmaString(bad))
    with pytest.raises(TransformFailure, match="not a hash"):
        run(HASHES, SigmaString("foo=bar"))
    with pytest.raises(TransformFailure, match="32 characters"):
        run(HASHES, SigmaString("IMPHASH=abc"), all_values=True)
    with pytest.warns(UserWarning, match="IMPHASH"):
        assert run(HASHES, SigmaString("IMPHASH=" + "a" * 32)) == []


def test_make_sets_original():
    value = one({"path_prefix": {"rewrite": [{"from": "C:", "to": "D:*"}]}}, r"C:\x")[1]
    assert value.original == str(value)


DEVPATH = {"path_prefix": {"rewrite": [{"from": "[A-Za-z]:", "to": r"\Device\HarddiskVolume*"}]}}


def test_path_prefix_drive_inside_pattern_fails():
    with pytest.raises(TransformFailure, match="cannot be rewritten"):
        run(DEVPATH, SigmaString(r"*C:\Users\*"))
    # No drive letter after the leading wildcard: unchanged.
    assert str(one(DEVPATH, r"*\Users\*")[1]) == r"*\Users\*"


VALUE_LEVEL = [
    {"map": {"values": {"a": 1}}},
    {"case": "lower"},
    "basename",
    DEVPATH,
    {"registry_path": {"hive": "kernel"}},
    {"regex_replace": {"pattern": "a", "replacement": "b"}},
    "to_int",
    "to_str",
    {"reject": {"pattern": "x", "reason": "r"}},
]
SUPPLIES_TARGETS = [
    HASHES,
    {"domain_user": {"domain": "d", "user": "u"}},
    {"registry_path": {"hive": "kernel", "split": {"key": "k", "value": "v"}}},
]


@pytest.mark.parametrize("value", [SigmaNull(), SigmaExists(True)])
@pytest.mark.parametrize("spec", VALUE_LEVEL)
def test_value_transforms_pass_null_and_exists(spec, value):
    assert run(spec, value) == [(T, value)]


@pytest.mark.parametrize("value", [SigmaNull(), SigmaExists(False)])
@pytest.mark.parametrize("spec", SUPPLIES_TARGETS)
def test_target_transforms_fail_on_null_and_exists(spec, value):
    with pytest.raises(TransformFailure, match=f"cannot be applied to {type(value).__name__}"):
        run(spec, value)


REJECT_PATTERN = r"^\*?(DWORD|QWORD) \(|^\*?Binary Data|^\*?\(?0x[0-9a-f]{1,16}\)?\*?$"
REJECT = {"reject": {"pattern": REJECT_PATTERN, "reason": "numeric values are not text"}}


def test_reject_matching_values_fail():
    for text in ("DWORD (0x00000001)", "*DWORD (0x00000000)*", "qword (0x1)", "Binary Data", "*binary data*"):
        with pytest.raises(TransformFailure, match="^numeric values are not text$"):
            run(REJECT, SigmaString(text))


def test_reject_other_values_pass():
    for text in ("*powershell*", "C:\\x.exe", "(Empty)", "*DWORD", "x DWORD (0x1)"):
        assert run(REJECT, SigmaString(text)) == [(T, SigmaString(text))]
    assert run(REJECT, SigmaNumber(1)) == [(T, SigmaNumber(1))]
    with pytest.raises(TransformFailure, match="numeric values"):
        run(REJECT, SigmaRegularExpression("^DWORD \\(0x0"))
    assert run(REJECT, SigmaRegularExpression("power.*shell"))[0][0] == T


def test_reject_bare_hex_numbers_fail():
    for text in ("0x00000001", "*0x00000001*", "*(0x00000001)", "(0x1)", "0xDEADBEEFDEADBEEF", "*0xff"):
        with pytest.raises(TransformFailure, match="^numeric values are not text$"):
            run(REJECT, SigmaString(text))
    for text in ("0x", "0x12345678901234567", "*0xzz*", "*x0x1*y", "1234", "*ab0x1*"):
        assert run(REJECT, SigmaString(text)) == [(T, SigmaString(text))]


def test_reject_regex_inline_flags():
    for rx in ("(?i)^DWORD \\(0x", "(?is)^DWORD \\(0x", "^DWORD \\(0x", "(?i)^Binary Data"):
        with pytest.raises(TransformFailure, match="numeric values"):
            run(REJECT, SigmaRegularExpression(rx))
    assert run(REJECT, SigmaRegularExpression("(?i)power.*shell"))[0][0] == T


def test_reject_params():
    for bad in ({"reject": {"pattern": "a"}}, {"reject": {"pattern": "(", "reason": "r"}},
                {"reject": {"pattern": "a", "reason": ""}}, {"reject": {"pattern": 1, "reason": "r"}}, "reject"):
        with pytest.raises(ValueError):
            parse_transform(bad, {})


def test_basename_contains_without_separator_fails():
    for text in ("*Microsoft Office*", "*tomcat*"):
        with pytest.raises(TransformFailure, match="basename cannot express a pattern on the directory"):
            run("basename", SigmaString(text))
    # A startswith-shaped value without a separator cannot be expressed either.
    for text in ("C:*", "cmd*", "cmd*x*"):
        with pytest.raises(TransformFailure, match="basename cannot express a pattern on the directory"):
            run("basename", SigmaString(text))
    # An endswith-shaped value stays as it is.
    assert str(one("basename", "*cmd.exe")[1]) == "*cmd.exe"
    assert str(one("basename", "cmd.exe")[1]) == "cmd.exe"


REG = {"registry_path": {"hive": "kernel"}}


@pytest.mark.parametrize(
    "text",
    [
        r"*HKLM\SOFTWARE\x*",
        r"*\hklm\SOFTWARE\x",
        r"*HKU\S-1\x",
        r"*HKCU\Software\x",
        r"*HKEY_LOCAL_MACHINE\SOFTWARE\x",
        r"*\REGISTRY\MACHINE\SOFTWARE\x",
        r"*\registry\user\S-1\x",
        r"*HKCR\x",
    ],
)
def test_registry_path_hive_inside_pattern_fails(text):
    with pytest.raises(TransformFailure, match="hive inside the pattern"):
        run(REG, SigmaString(text))


def test_registry_path_wildcard_without_hive_unchanged():
    for text in (r"*\SOFTWARE\Microsoft\Run\*", r"*\HKLMX\a", r"*SHKU\x", "*HKLM"):
        assert str(one(REG, text)[1]) == text


SPLIT = {"registry_path": {"hive": "kernel", "split": {"key": "k", "value": "v"}}}


def test_registry_path_split_default_value_fails():
    for text in (r"HKLM\SOFTWARE\x\(Default)", r"*\Run\(default)", r"*\x\(Default)*"):
        with pytest.raises(TransformFailure, match=r"the \(Default\) value name cannot be matched"):
            run(SPLIT, SigmaString(text))
    for text in ("*(Default)", "(Default)", "*(DEFAULT)", "x(default)"):
        with pytest.raises(TransformFailure, match=r"the \(Default\) value name cannot be matched"):
            run(SPLIT, SigmaString(text))
    # Without split the value is matched as it is.
    assert str(one(REG, r"*\x\(Default)")[1]) == r"*\x\(Default)"


def test_expansion_message():
    from sigma.types import SigmaExpansion

    with pytest.raises(TransformFailure, match=r"^expanded values \(windash/base64offset\) are not supported$"):
        run("basename", SigmaExpansion([SigmaString("a"), SigmaString("b")]))


DEVPATH_KEEP = {
    "path_prefix": {"rewrite": [{"from": "[A-Za-z]:", "to": r"\Device\HarddiskVolume*"}], "keep_original": True}
}


def _strs(alternatives):
    return [str(v) for _, v in alternatives]


def test_path_prefix_keep_original():
    assert _strs(run(DEVPATH_KEEP, SigmaString(r"C:\x\y.exe"))) == [r"C:\x\y.exe", r"\Device\HarddiskVolume*\x\y.exe"]
    assert _strs(run(DEVPATH_KEEP, SigmaString(r"*\y.exe"))) == [r"*\y.exe"]
    # The drive letter inside a leading-wildcard pattern still fails.
    with pytest.raises(TransformFailure, match="cannot be rewritten"):
        run(DEVPATH_KEEP, SigmaString(r"*C:\Users\*"))


def test_path_prefix_keep_original_must_be_bool():
    with pytest.raises(ValueError, match="keep_original"):
        parse_transform({"path_prefix": {"rewrite": [{"from": "C:", "to": "D:"}], "keep_original": "yes"}}, {})


SUFFIX = {"basename": {"also_suffix": True}}


def test_basename_also_suffix():
    with pytest.warns(UserWarning, match="directory dropped"):
        assert _strs(run(SUFFIX, SigmaString(r"C:\x\cmd.exe"))) == ["cmd.exe", r"*\cmd.exe"]
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert _strs(run(SUFFIX, SigmaString(r"*\cmd.exe"))) == ["cmd.exe", r"*\cmd.exe"]
        assert _strs(run(SUFFIX, SigmaString("cmd.exe"))) == ["cmd.exe", r"*\cmd.exe"]
        # An endswith value without a separator already matches both forms.
        assert _strs(run(SUFFIX, SigmaString("*cmd.exe"))) == ["*cmd.exe"]
    alternatives = run(SUFFIX, SigmaString(r"*\cmd.exe"))
    assert alternatives[1][1].s[0] is SpecialChars.WILDCARD_MULTI
    with pytest.warns(UserWarning, match="may span directories"):
        assert _strs(run(SUFFIX, SigmaString(r"*\py*.exe"))) == ["py*.exe", r"*\py*.exe"]
    with pytest.raises(TransformFailure, match="basename cannot express"):
        run(SUFFIX, SigmaString("cmd*"))


def test_basename_params():
    assert len(parse_transform("basename", {})) == 1
    assert len(parse_transform({"basename": {}}, {})) == 1
    assert len(parse_transform({"basename": {"also_suffix": False}}, {})) == 1
    with pytest.raises(ValueError, match="unknown parameter"):
        parse_transform({"basename": {"nope": True}}, {})
    with pytest.raises(ValueError, match="also_suffix"):
        parse_transform({"basename": {"also_suffix": 1}}, {})
    # Without also_suffix the result is a single alternative, as before.
    assert _strs(run("basename", SigmaString("cmd.exe"))) == ["cmd.exe"]


def test_basename_also_suffix_inner_wildcard_without_separator():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert _strs(run(SUFFIX, SigmaString("py*.exe"))) == ["py*.exe", r"*\py*.exe"]
        assert _strs(run(SUFFIX, SigmaString("?md.exe"))) == ["?md.exe", r"*\?md.exe"]
        assert _strs(run(SUFFIX, SigmaString("cmd.e?e"))) == ["cmd.e?e", r"*\cmd.e?e"]
        assert _strs(run(SUFFIX, SigmaString("*"))) == ["*"]
    alternatives = run(SUFFIX, SigmaString("?md.exe"))
    assert alternatives[1][1].s[2] is SpecialChars.WILDCARD_SINGLE


def test_basename_also_suffix_forward_slash():
    with pytest.warns(UserWarning, match="directory dropped"):
        assert _strs(run(SUFFIX, SigmaString("/usr/bin/bash"))) == ["bash", r"*\bash", "*/bash"]
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert _strs(run(SUFFIX, SigmaString("*/bash"))) == ["bash", r"*\bash", "*/bash"]
        assert _strs(run(SUFFIX, SigmaString(r"*\bash"))) == ["bash", r"*\bash"]


def test_path_prefix_keep_original_unknown_param():
    with pytest.raises(ValueError, match="unknown parameter"):
        parse_transform(
            {"path_prefix": {"rewrite": [{"from": "C:", "to": "D:"}], "keep_original": True, "nope": 1}}, {}
        )


# --- join transform --------------------------------------------------------------------------


def _join_profile(tmp_path, join):
    (tmp_path / "j.yml").write_text(
        "profile: joinp\nversion: 1\nparser: akamai_waf\nfields:\n"
        f"  u: {{transform: {{join: {join}}}}}\n"
        "logsources:\n  - match: {category: webserver}\n"
    )
    return str(tmp_path)


_JOIN = "{parts: [httpMessage.path, httpMessage.query], sep: '?'}"


def _join_sql(tmp_path, detection, join=_JOIN):
    rule = SigmaCollection.from_yaml(
        "title: T\nstatus: test\nlogsource:\n    category: webserver\n"
        f"detection:\n    sel:\n        {detection}\n    condition: sel\n"
    ).rules[0]
    backend = DatabricksBackend(
        parsers="joinp",
        table_name="t",
        catalog_name="c",
        schema_name="s",
        lakewatch_profiles_dir=_join_profile(tmp_path, join),
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return json.loads(backend.convert_rule(rule, "lakewatch")[0])["sql"]


JOIN_EXPR = "concat_ws('?', nullif(httpMessage.path, ''), nullif(httpMessage.query, ''))"


def test_join_transform_apply():
    spec = {"join": {"parts": ["a", "b"], "sep": "?"}}
    targets, value = one(spec, "/a?b=1")
    assert targets == (join_field_name("?", ["a", "b"]),)
    assert str(value) == "/a?b=1"
    assert parse_transform(spec, {})[0].required_paths() == ("a", "b")


def test_join_eq(tmp_path):
    sql = _join_sql(tmp_path, "u: '/a\\?b=1'")
    assert sql == f"SELECT *\nFROM t\nWHERE IN_TIMERANGE(time)\n  AND (lower({JOIN_EXPR}) = lower('/a?b=1'))"


def test_join_modifiers(tmp_path):
    for mod in ("contains", "endswith", "startswith", "re"):
        assert JOIN_EXPR in _join_sql(tmp_path, f"u|{mod}: 'a'"), mod


def test_join_empty_part(tmp_path):
    sql = _join_sql(tmp_path, "u: 'x'")
    assert "nullif(httpMessage.path, '')" in sql
    assert "nullif(httpMessage.query, '')" in sql


@pytest.mark.parametrize(
    "params",
    [
        {"parts": ["a"], "sep": "?"},
        {"parts": ["a", "b", "c"], "sep": "?"},
        {"parts": "ab", "sep": "?"},
    ],
)
def test_join_validation_parts(params):
    with pytest.raises(ValueError, match="parts"):
        parse_transform({"join": params}, {})


@pytest.mark.parametrize(
    "params", [{"parts": ["a", "b"]}, {"parts": ["a", "b"], "sep": ""}, {"parts": ["a", "b"], "sep": 3}]
)
def test_join_validation_sep(params):
    with pytest.raises(ValueError, match="sep"):
        parse_transform({"join": params}, {})


def test_join_validation_non_scalar_at_load(tmp_path):
    d = _join_profile(tmp_path, "{parts: [httpMessage, httpMessage.query], sep: '?'}")
    profile = load_profiles([d])["joinp"]
    schema = SchemaCatalog.load(()).get("akamai_waf")
    with pytest.raises(ProfileError, match="join parts must be scalar fields"):
        validate_profile(profile, schema)
    # The backend runs this validation before converting any rule.
    with pytest.raises(ProfileError, match="join parts must be scalar fields"):
        _join_sql(tmp_path, "u: 'x'", join="{parts: [httpMessage, httpMessage.query], sep: '?'}")
