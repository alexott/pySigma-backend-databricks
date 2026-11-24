import warnings

import pytest
from sigma.rule import SigmaLogSource

from sigma.backends.databricks.schema_catalog import ParserSchema, PathInfo, SchemaCatalog
from sigma.pipelines.databricks.lakewatch.profile import (
    FieldMapping,
    Profile,
    ProfileError,
    load_profiles,
    parse_profile,
    validate_profile,
)


def base(**over):
    data = {
        "profile": "p",
        "version": 1,
        "parser": "x",
        "fields": {"A": "a", "B": ["b", "c"], "C": {"field": "c"}},
        "logsources": [{"match": {"product": "aws"}}],
    }
    data.update(over)
    return data


def schema():
    return ParserSchema(
        "x",
        None,
        None,
        {
            "a": PathInfo("STRING", "column"),
            "b": PathInfo("STRING", "column"),
            "c": PathInfo("INT", "column"),
            "EventID": PathInfo("STRING", "column", allowed=("1", "7")),
            "v": PathInfo("VARIANT", "column"),
            "s": PathInfo("STRUCT", "column"),
            "s.k": PathInfo("STRING", "struct"),
        },
    )


def test_parse_minimal_profile():
    p = parse_profile(base(), "<dict>")
    assert len(p.logsources) == 1
    assert p.fields["A"] == FieldMapping(("a",))
    assert p.fields["B"] == FieldMapping(("b", "c"))
    assert p.fields["C"] == FieldMapping(("c",))
    assert list(p.fields) == ["A", "B", "C"]


def test_parse_rejects_unknown_key():
    with pytest.raises(ProfileError, match="unknown key 'table'"):
        parse_profile(base(table="x"), "f.yml")


def test_parse_errors_have_source_prefix_and_required_keys():
    with pytest.raises(ProfileError, match=r"^f.yml: "):
        parse_profile({"profile": "p"}, "f.yml")
    with pytest.raises(ProfileError, match="logsources"):
        parse_profile(base(logsources=[]), "<dict>")
    with pytest.raises(ProfileError, match="unknown key 'x'"):
        parse_profile(base(fields={"A": {"field": "a", "x": 1}}), "<dict>")
    with pytest.raises(ProfileError, match="match"):
        parse_profile(base(logsources=[{"match": {"foo": "bar"}}]), "<dict>")


def test_duplicate_match_rejected():
    ls = [{"match": {"product": "aws"}}, {"match": {"product": "aws"}}]
    with pytest.raises(ProfileError, match="duplicate"):
        parse_profile(base(logsources=ls), "<dict>")


def test_block_for_most_specific():
    ls = [
        {"match": {"product": "aws"}},
        {"match": {"product": "aws", "service": "cloudtrail"}},
    ]
    p = parse_profile(base(logsources=ls), "<dict>")
    assert p.block_for(SigmaLogSource(product="aws", service="cloudtrail")) is p.logsources[1]
    assert p.block_for(SigmaLogSource(product="AWS", service="s3")) is p.logsources[0]
    assert p.block_for(SigmaLogSource(product="gcp")) is None
    assert p.block_for(SigmaLogSource(service="cloudtrail")) is None


def test_block_for_tie_first_wins():
    ls = [{"match": {"category": "process_creation"}}, {"match": {"product": "windows"}}]
    p = parse_profile(base(logsources=ls), "<dict>")
    ls_ = SigmaLogSource(product="windows", category="process_creation")
    assert p.block_for(ls_) is p.logsources[0]


def test_mappings_block_overrides_profile():
    ls = [{"match": {"product": "aws"}, "fields": {"A": "b", "Z": "c"}}]
    p = parse_profile(base(logsources=ls), "<dict>")
    m = p.mappings_for(p.logsources[0])
    assert m["A"].targets == ("b",)
    assert m["Z"].targets == ("c",)
    assert m["B"].targets == ("b", "c")


def prof(fields=None, block=None):
    b = {"match": {"product": "aws"}}
    b.update(block or {})
    return parse_profile(base(fields=fields or {}, logsources=[b]), "<dict>")


def test_validate_ok():
    validate_profile(prof({"A": "a", "S": "s.k", "V": "v", "W": "v.deep.er"}), schema())


def test_validate_unknown_target():
    with pytest.raises(ProfileError, match="'Q'.*nope"):
        validate_profile(prof({"Q": "nope"}), schema())


def test_validate_block_fields_and_unknown_condition_field():
    with pytest.raises(ProfileError, match="nope"):
        validate_profile(prof(block={"fields": {"Q": "nope"}}), schema())
    with pytest.raises(ProfileError, match="nope"):
        validate_profile(prof(block={"conditions": {"nope": "1"}}), schema())


def test_validate_condition_value_not_allowed():
    validate_profile(prof(block={"conditions": {"EventID": ["1", "7"]}}), schema())
    with pytest.raises(ProfileError, match="'11' not in allowed"):
        validate_profile(prof(block={"conditions": {"EventID": "11"}}), schema())
    with pytest.raises(ProfileError, match="'11' not in allowed"):
        validate_profile(prof(block={"conditions": {"EventID": 11}}), schema())


def test_validate_prefix_mapping_requires_freeform_variant():
    validate_profile(prof({"v.*": "v.*"}), schema())
    with pytest.raises(ProfileError, match="prefix mapping requires a free-form VARIANT"):
        validate_profile(prof({"s.*": "s.*"}), schema())
    with pytest.raises(ProfileError, match="prefix mapping requires"):
        validate_profile(prof({"a.*": "a.*"}), schema())
    with pytest.raises(ProfileError, match="prefix"):
        validate_profile(prof({"v.*": "v"}), schema())


def test_validate_unsupported_not_mapped():
    validate_profile(prof({"A": "a"}, {"unsupported": ["Z"]}), schema())
    with pytest.raises(ProfileError, match="'A'.*unsupported"):
        validate_profile(prof({"A": "a"}, {"unsupported": ["A"]}), schema())


def test_validate_emits_no_warnings():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        validate_profile(prof({"A": "S.K"}), schema())


def test_validate_against_builtin_catalog():
    s = SchemaCatalog.load().get("aws_cloudtrail")
    validate_profile(
        prof(
            {
                "eventName": "eventName",
                "arn": "userIdentity.arn",
                "requestParameters.*": "requestParameters.*",
            }
        ),
        s,
    )
    with pytest.raises(ProfileError, match="prefix mapping requires"):
        validate_profile(prof({"userIdentity.*": "userIdentity.*"}), s)


def write(d, name, pid, target):
    (d / name).write_text(
        f"profile: {pid}\nversion: 1\nparser: x\nfields:\n  A: {target}\n"
        "logsources:\n  - match: {product: aws}\n"
    )


def test_load_profiles_user_dir_overrides_builtin(tmp_path):
    base_ = load_profiles()
    d1 = tmp_path / "d1"
    d2 = tmp_path / "d2"
    d1.mkdir()
    d2.mkdir()
    write(d1, "a.yml", "same", "one")
    write(d2, "b.yml", "same", "two")
    profiles = load_profiles([str(d1), str(d2)])
    assert profiles["same"].fields["A"].targets == ("two",)
    assert profiles["same"].source.endswith("b.yml")
    assert set(base_) <= set(profiles)


def test_load_profiles_errors(tmp_path):
    with pytest.raises(ProfileError, match="does not exist"):
        load_profiles([str(tmp_path / "missing")])
    write(tmp_path, "a.yml", "dup", "x")
    write(tmp_path, "b.yml", "dup", "y")
    with pytest.raises(ProfileError, match="dup"):
        load_profiles([str(tmp_path)])


def test_star_target_requires_prefix_key():
    with pytest.raises(ProfileError, match=r"f.yml: field 'star': .*'\.\*'.*prefix key"):
        parse_profile(base(fields={"star": "requestParameters.*"}), "f.yml")
    with pytest.raises(ProfileError, match="field 'star'"):
        parse_profile(base(fields={"star": ["a", "requestParameters.*"]}), "f.yml")


@pytest.mark.parametrize("pid", ["My-CT", "UPPER", "with space", "dash-ed", "a.b", "x" * 65, "ü"])
def test_profile_id_must_be_uc_safe(pid):
    with pytest.raises(ProfileError, match=r"f.yml: 'profile' must match"):
        parse_profile(base(profile=pid), "f.yml")


@pytest.mark.parametrize("pid", ["aws_cloudtrail", "p1", "x" * 64])
def test_profile_id_accepted(pid):
    assert parse_profile(base(profile=pid), "f.yml").profile == pid


@pytest.mark.parametrize("content, match", [
    ("profile: [unclosed\n", "invalid YAML"),
    ("", "profile file is empty"),
    ("# only a comment\n", "profile file is empty"),
])
def test_load_profiles_bad_file_content(tmp_path, content, match):
    path = tmp_path / "bad.yml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ProfileError, match=match) as exc:
        load_profiles([str(tmp_path)])
    assert str(exc.value).startswith(f"{path}: ")


def test_load_profiles_undecodable_file(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_bytes(b"profile: \xff\xfe\n")
    with pytest.raises(ProfileError, match="cannot read profile file") as exc:
        load_profiles([str(tmp_path)])
    assert str(exc.value).startswith(f"{path}: ")


def test_load_profiles_unreadable_file(tmp_path):
    path = tmp_path / "dir.yml"
    path.mkdir()  # reading a directory raises an OSError on every platform
    with pytest.raises(ProfileError, match="cannot read profile file") as exc:
        load_profiles([str(tmp_path)])
    assert str(exc.value).startswith(f"{path}: ")
