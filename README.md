![Tests](https://github.com/alexott/databricks-sigma-backend/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/alexott/GitHub Gist identifier containing coverage badge JSON expected by shields.io./raw/alexott-databricks-sigma-backend.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

Status: **experimental**, work in progress:

* Requires more testing

# pySigma Databricks Backend

This is the Databricks backend for pySigma. It provides the package `sigma.backends.databricks` with the `DatabricksBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.databricks`:

* `snake_case`: convert column names into snake case format

It supports the following output formats:

* default: plain Databricks/Apache Spark SQL queries
* dbsql: Databricks SQL queries with rules metadata (title, status) embedded as comment
* detection_yaml: Yaml markup for my own detection framework
* lakewatch: Lakewatch detection rules (`kind: Rule` YAML), batch by default

## CIDR Matching

The `|cidr` modifier is converted using the built-in Databricks IP functions
[`ip_cidr_contains`](https://docs.databricks.com/aws/en/sql/language-manual/functions/ip_cidr_contains)
and `try_ip_as_binary` (Databricks Runtime 18.2+, IPv4 and IPv6). Field values that aren't valid
IP addresses evaluate to `NULL` instead of failing the query. Note that, following SQL `NULL`
semantics, such rows don't match the negated condition either (e.g. `condition: not sel`), so they
are excluded from both `sel` and `not sel` results:

```yaml
detection:
    sel:
        src_ip|cidr: 192.168.0.0/16
    condition: sel
```
Generates: `ip_cidr_contains('192.168.0.0/16', try_ip_as_binary(src_ip))`

For other Spark SQL engines (e.g. open source Apache Spark), override the expression with the
`cidr_expression` option. It's a format string with the placeholders `{field}`, `{value}`
(whole CIDR), `{network}`, `{prefixlen}` and `{netmask}`:

```bash
sigma convert -t databricks -O "cidr_expression=cidrmatch({field}, '{value}')" rule.yml
```

```python
backend = DatabricksBackend(cidr_expression="cidrmatch({field}, '{value}')")
```

You need to register the corresponding function (here `cidrmatch`) as a UDF yourself.

## Unbound Keyword Search

The backend supports Sigma rules with unbound keywords (values without field names). These keywords search the raw log line.

### Configuration

By default, the backend looks for keywords in a field named `raw` (`raw_data` when the
target is OCSF, see [OCSF field rendering](#ocsf-field-rendering)). You can customize this:

**Command Line:**
```bash
sigma convert -t databricks -O raw_log_field=message rule.yml
```

**Programmatic:**
```python
from sigma.backends.databricks import DatabricksBackend

backend = DatabricksBackend(raw_log_field="event_data")
```

### Examples

**Simple Keywords (OR logic):**
```yaml
detection:
    keywords:
        - 'EVILSERVICE'
        - 'svchost.exe -n evil'
    condition: keywords
```
Generates: `contains(lower(raw), lower('EVILSERVICE')) OR contains(lower(raw), lower('svchost.exe -n evil'))`

**Keywords with |all (AND logic):**
```yaml
detection:
    keywords:
        '|all':
            - 'Remove-MailboxExportRequest'
            - ' -Identity '
    condition: keywords
```
Generates: `contains(lower(raw), lower('Remove-MailboxExportRequest')) AND contains(lower(raw), lower(' -Identity '))`

**Mixed with Field Conditions:**
```yaml
detection:
    selection:
        EventID: 4688
    keywords:
        - 'mimikatz'
    condition: selection and keywords
```
Generates: `EventID = 4688 AND contains(lower(raw), lower('mimikatz'))`

**Wildcards in Keywords:**
```yaml
detection:
    keywords:
        - '*malware*'      # uses contains()
        - 'cmd.exe*'       # uses startswith()
        - '*.dll'          # uses endswith()
    condition: keywords
```

**Regex Patterns:**
```yaml
detection:
    keywords:
        - '|re': '.*evil(cmd|powershell).*'
    condition: keywords
```
Generates: `raw rlike '.*evil(cmd|powershell).*'`

## Lakewatch Output

Generate [Lakewatch](https://docs.databricks.com) detection rules (`kind: Rule` YAML)
from Sigma rules. Intended to run **after** the
[OCSF pipeline](https://github.com/SigmaHQ/pySigma-pipeline-ocsf), which normalizes
fields and injects the OCSF class, so the backend can pick the gold table.

```bash
sigma convert -t databricks -f lakewatch -p ocsf rules/ -o detections.yaml
```

Multiple rules are emitted as separate `---` documents in one file.

### Options (`-O key=value`)

| Option | Default | Meaning |
|--------|---------|---------|
| `table_name` | *(derived)* | FROM table. If unset, derived from the OCSF class the pipeline injected; error if neither is available. |
| `lookback` | `25 HOUR` | Batch window (Spark interval syntax) in the `time >= now - INTERVAL <lookback>` predicate. |
| `schedule` | `24h` | `spec.schedule.atLeastEvery` (Lakewatch duration). |
| `compute_group` | `automatic` | `spec.schedule.computeGroup`. |
| `default_fidelity` | *(from status)* | Override `spec.metadata.fidelity`. |
| `default_category` | `Static Signature` | `spec.metadata.category`. |

```bash
sigma convert -t databricks -f lakewatch -p ocsf \
  -O table_name=main.security.authentication -O lookback="1 DAY" -O schedule=12h rule.yml
```

Sigma metadata maps to Lakewatch as: `title`→`displayName`, `description`→`comment`/`objective`,
`level`→`severity`, `status`→`fidelity`, and `attack.*` tags→`mitre`. Only batch rules are
generated (streaming is future work).

## OCSF field rendering

When the target schema is OCSF, the dotted field names produced by the OCSF pipeline are rendered
according to the OCSF attribute types (tables bundled from OCSF 1.9.0, refresh them with
`python scripts/gen_ocsf_attributes.py [VERSION]`):

* Paths through OCSF **array** attributes (`hashes`, `answers`, `evidences`, `resources`, …) are
  matched against any element:
  `process.file.hashes.value: abc` → `exists(process.file.hashes, x0 -> lower(x0.value) = lower('abc'))`.
  Each condition gets its own `exists()`, so two conditions on the same array may match
  different elements.
* Paths into **free-form** attributes (`unmapped`, `xattributes` and `json_t` attributes such as
  `data`) use the Databricks JSON path syntax, which works for VARIANT and JSON string columns:
  `unmapped.Initiated: 'true'` → `lower(unmapped:Initiated::string) = lower('true')`. Numbers and
  booleans are compared via `try_cast(... AS DOUBLE)` / `try_cast(... AS BOOLEAN)`.
* Unbound keywords search the OCSF `raw_data` field unless `raw_log_field` is set explicitly.

This is controlled by the `ocsf` option (`-O ocsf=true|false|auto`). With the default `auto` it is
enabled for the `lakewatch` format and for rules processed by the OCSF pipeline (`-p ocsf`).

## Maintainer

This backend is currently maintained by:

* [Alex Ott](https://github.com/alexott/)
