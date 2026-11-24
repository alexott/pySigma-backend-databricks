import importlib.util
from pathlib import Path

ROOT = Path(__file__).parent.parent
PACK = Path(__file__).parent / "data" / "parsers"


def _load():
    spec = importlib.util.spec_from_file_location(
        "gen_lakewatch_v2_schemas", ROOT / "scripts" / "gen_lakewatch_v2_schemas.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_catalog_demo():
    catalog = _load().build_catalog(PACK)
    demo = catalog["parsers"]["demo"]
    assert demo["uuid"] == "11111111-2222-3333-4444-555555555555"
    assert demo["version"] == 3
    paths = demo["paths"]
    for managed in ("time", "lw_id", "lw_meta", "lw_observables"):
        assert managed in paths
    assert paths["time"] == {"type": "TIMESTAMP", "storage": "column"}
    expected = {
        "eventName": {"type": "STRING", "storage": "column", "required": True},
        "EventID": {"type": "STRING", "storage": "column", "allowed": ["1", "7"]},
        "userIdentity": {"type": "VARIANT", "storage": "column"},
        "userIdentity.arn": {"type": "STRING", "storage": "variant"},
        "userIdentity.sessionContext": {"type": "VARIANT", "storage": "variant"},
        "userIdentity.sessionContext.attributes": {"type": "VARIANT", "storage": "variant"},
        "userIdentity.sessionContext.attributes.mfaAuthenticated": {"type": "STRING", "storage": "variant"},
        "actor": {"type": "STRUCT", "storage": "column"},
        "actor.alternateId": {"type": "STRING", "storage": "struct"},
        "resources": {"type": "ARRAY", "storage": "column", "element": "VARIANT"},
        "resources[].arn": {"type": "STRING", "storage": "variant"},
        "event": {"type": "VARIANT", "storage": "column"},
    }
    for path, info in expected.items():
        assert paths[path] == info, path
    assert set(paths) - set(expected) == {"time", "lw_id", "lw_meta", "lw_observables"}


def test_missing_index_files(tmp_path):
    (tmp_path / "parsers" / "x").mkdir(parents=True)
    (tmp_path / "parsers" / "x" / "parser.yaml").write_text("fields:\n  - name: a\n")
    x = _load().build_catalog(tmp_path)["parsers"]["x"]
    assert x["uuid"] is None and x["version"] is None
    assert x["paths"]["a"] == {"type": "STRING", "storage": "column"}
