"""Tests for the Lakewatch profile value transforms."""

import warnings

import pytest
from sigma.types import (
    SigmaBool,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from sigma.backends.databricks.field_paths import join_field_name
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
    with pytest.warns(UserWarning, match="wildcard in the file name"):
        assert str(one("basename", r"C:\x\a*b.exe")[1]) == "a*b.exe"


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
