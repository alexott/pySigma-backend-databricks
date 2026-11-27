# OCSF mode

OCSF mode is optional. By default, Lakewatch rules are converted against the tables of Lakewatch
parsers (see the [README](../README.md#lakewatch-quick-start)).


Instead of parser tables, Lakewatch rules can be converted against the OCSF gold tables. OCSF mode
is selected with `-p ocsf` or `-O ocsf=true`. The backend then runs **after** the
[OCSF pipeline](https://github.com/SigmaHQ/pySigma-pipeline-ocsf), which normalizes the fields and
injects the OCSF class, so the backend can pick the gold table:

```bash
sigma convert -t databricks -f lakewatch -p ocsf \
  -O catalog_name=main -O schema_name=security -O warehouse_id=1234567890abcdef rules/ -o detections.yaml
```

* The FROM table is the gold table of the OCSF class the pipeline injected (for example
  `process_activity`). `-O table_name=...` overrides it. Conversion fails if neither is available.
* The options of [Lakewatch options](../README.md#lakewatch-options) apply. The parsed-table options (`parsers`,
  `table_map`, `lakewatch_profiles_dir`, `lakewatch_schemas`) don't: `-O parsers` together with
  OCSF mode is a configuration error.
* Target modes, profile entities and summary overrides need parsed tables: `-O target=content_pack`
  fails in OCSF mode, `-O overrides` is ignored with a warning, and the summary is the rule title.
* With `-O output_dir`, one file per rule and `conversion_report.yaml` are written as in parsed
  mode (`profile` is `null` in the report).


## OCSF field rendering

When the target schema is OCSF, the dotted field names produced by the OCSF pipeline are rendered
according to the OCSF attribute types (tables bundled from OCSF 1.9.0, refresh them with
`python scripts/gen_ocsf_attributes.py [VERSION]`):

* Paths through OCSF **array** attributes (`hashes`, `answers`, `evidences`, `resources`, …) are
  matched against any element:
  `process.file.hashes.value: abc` → `exists(process.file.hashes, x0 -> lower(x0.value) = 'abc')`.
  Each condition gets its own `exists()`, so two conditions on the same array may match
  different elements.
* Paths into **free-form** attributes (`unmapped`, `xattributes` and `json_t` attributes such as
  `data`) use the Databricks JSON path syntax, which works for VARIANT and JSON string columns:
  `unmapped.Initiated: 'true'` → `lower(unmapped:Initiated::string) = 'true'`. Numbers and
  booleans are compared via `try_cast(... AS DOUBLE)` / `try_cast(... AS BOOLEAN)`.
* Unbound keywords search the OCSF `raw_data` field unless `raw_log_field` is set explicitly.

This is controlled by the `ocsf` option (`-O ocsf=true|false|auto`). With the default `auto` it is
enabled for rules processed by the OCSF pipeline (`-p ocsf`). For `lakewatch` without OCSF,
[parsed tables](writing-profiles.md) are used.
