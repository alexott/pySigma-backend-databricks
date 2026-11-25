"""Tests for Lakewatch mapping profile parsing, loading and validation."""

import warnings

import pytest
from sigma.rule import SigmaLogSource

from sigma.backends.databricks.schema_catalog import ParserSchema, PathInfo, SchemaCatalog
from sigma.pipelines.databricks.lakewatch.profile import (
    FieldMapping,
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


def test_validate_named_entry_target():
    validate_profile(prof({"Image": "v[Image]"}), schema())
    with pytest.raises(ProfileError, match="'Image'.*a\\[Image\\].*VARIANT or ARRAY"):
        validate_profile(prof({"Image": "a[Image]"}), schema())


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
        f"profile: {pid}\nversion: 1\nparser: x\nfields:\n  A: {target}\nlogsources:\n  - match: {{product: aws}}\n"
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


@pytest.mark.parametrize(
    "content, match",
    [
        ("profile: [unclosed\n", "invalid YAML"),
        ("", "profile file is empty"),
        ("# only a comment\n", "profile file is empty"),
    ],
)
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


# --- transforms, select_condition, modifiers, undeclared, products ---------------------


def schema2():
    s = schema()
    paths = dict(s.paths)
    paths.update(
        {
            "w": PathInfo("VARIANT", "column"),
            "w.known": PathInfo("STRING", "variant"),
            "md5": PathInfo("STRING", "column"),
            "flag": PathInfo("BOOLEAN", "column"),
        }
    )
    return ParserSchema("x", None, None, paths)


def test_parse_named_and_inline_transforms():
    p = parse_profile(
        base(
            transforms={"reg": {"registry_path": {"hive": "kernel"}}},
            fields={"K": {"field": "a", "transform": ["reg", {"case": "lower"}]}},
        )
    )
    assert len(p.fields["K"].transforms) == 2
    assert list(p.transforms) == ["reg"]
    assert len(p.transforms["reg"]) == 1


def test_parse_bad_transform_wrapped():
    with pytest.raises(ProfileError, match="field 'K': .*nope"):
        parse_profile(base(fields={"K": {"field": "a", "transform": {"nope": 1}}}))


def test_parse_supplies_targets_forbids_field():
    spec = {"field": "x", "transform": {"hashes": {"algos": {"MD5": "m"}}}}
    with pytest.raises(ProfileError, match="field"):
        parse_profile(base(fields={"H": spec}))
    p = parse_profile(base(fields={"H": {"transform": {"hashes": {"algos": {"MD5": "m"}}}}}))
    assert p.fields["H"].targets == ()


def test_parse_missing_field():
    with pytest.raises(ProfileError, match="missing key 'field'"):
        parse_profile(base(fields={"H": {"transform": "basename"}}))


def test_parse_select_condition():
    p = parse_profile(base(fields={"S": {"select_condition": {"A": {"X": 1}, "B": {"Y": "z"}}}}))
    assert p.fields["S"].select == {"a": {"X": 1}, "b": {"Y": "z"}}
    assert p.fields["S"].targets == ()
    with pytest.raises(ProfileError, match="select_condition"):
        parse_profile(base(fields={"S": {"select_condition": {"a": {"X": 1}}, "field": "a"}}))
    with pytest.raises(ProfileError, match="select_condition"):
        parse_profile(base(fields={"S": {"select_condition": {"a": {"X": 1}}, "transform": "basename"}}))


def test_parse_unknown_modifier():
    with pytest.raises(ProfileError, match="fancy"):
        parse_profile(base(fields={"M": {"field": "a", "modifiers": ["eq", "fancy"]}}))
    p = parse_profile(base(fields={"M": {"field": "a", "modifiers": ["eq", "contains"]}}))
    assert p.fields["M"].modifiers == frozenset({"eq", "contains"})


def test_parse_prefix_key_allows_only_field():
    with pytest.raises(ProfileError, match="prefix"):
        parse_profile(base(fields={"v.*": {"field": "v.*", "modifiers": ["eq"]}}))
    with pytest.raises(ProfileError, match="prefix"):
        parse_profile(base(fields={"v.*": {"field": "v.*", "undeclared": True}}))


def test_products_conditions_merge():
    p = parse_profile(
        base(
            products={"Windows": {"a": "Win", "b": "x"}},
            logsources=[{"match": {"category": "process_creation"}, "conditions": {"b": "y"}}],
        )
    )
    assert list(p.products) == ["windows"]
    ls = SigmaLogSource(category="process_creation", product="windows")
    block = p.block_for(ls)
    assert p.conditions_for(block, ls) == {"a": "Win", "b": "y"}
    assert list(p.conditions_for(block, ls)) == ["a", "b"]


def test_products_unlisted_product_no_match():
    p = parse_profile(
        base(
            products={"windows": {"a": "Win"}},
            logsources=[{"match": {"category": "process_creation"}}],
        )
    )
    assert p.block_for(SigmaLogSource(category="process_creation", product="linux")) is None
    assert p.block_for(SigmaLogSource(category="process_creation")) is not None
    assert p.block_for(SigmaLogSource(category="process_creation", product="Windows")) is not None


def test_bool_condition_value():
    p = parse_profile(base(logsources=[{"match": {"product": "aws"}, "conditions": {"flag": False}}]))
    assert p.logsources[0].conditions == {"flag": False}
    validate_profile(p, schema2())
    with pytest.raises(ProfileError, match="condition"):
        parse_profile(base(logsources=[{"match": {"product": "aws"}, "conditions": {"flag": {}}}]))
    p2 = parse_profile(base(products={"windows": {"flag": True}}))
    validate_profile(p2, schema2())


def test_validate_transform_paths():
    spec = {"transform": {"hashes": {"algos": {"MD5": "md5"}}}}
    validate_profile(prof({"H": spec}), schema2())
    bad = {"transform": {"hashes": {"algos": {"MD5": "nope"}}}}
    with pytest.raises(ProfileError, match="nope"):
        validate_profile(prof({"H": bad}), schema2())


def test_validate_select_and_products_conditions():
    validate_profile(prof({"S": {"select_condition": {"a": {"EventID": "1"}}}}), schema2())
    with pytest.raises(ProfileError, match="'11' not in allowed"):
        validate_profile(prof({"S": {"select_condition": {"a": {"EventID": "11"}}}}), schema2())
    with pytest.raises(ProfileError, match="nope"):
        validate_profile(prof({"S": {"select_condition": {"a": {"nope": "1"}}}}), schema2())
    p = parse_profile(base(products={"windows": {"EventID": "11"}}))
    with pytest.raises(ProfileError, match="'11' not in allowed"):
        validate_profile(p, schema2())


def test_validate_undeclared():
    validate_profile(prof({"U": {"field": "w.other", "undeclared": True}}), schema2())
    with pytest.raises(ProfileError, match="w.other"):
        validate_profile(prof({"U": "w.other"}), schema2())
    with pytest.raises(ProfileError, match="'undeclared' is not needed"):
        validate_profile(prof({"U": {"field": "w.known", "undeclared": True}}), schema2())
