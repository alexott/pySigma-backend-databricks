![Tests](https://github.com/alexott/databricks-sigma-backend/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/alexott/GitHub Gist identifier containing coverage badge JSON expected by shields.io./raw/alexott-databricks-sigma-backend.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

Status: **experimental**, work in progress:

* Requires more testing

# pySigma Databricks Backend

This is the Databricks backend for pySigma. It provides the package `sigma.backends.databricks` with the `DatabricksBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.databricks`:

* `snake_case`: convert column names into snake case format

See [CHANGELOG.md](CHANGELOG.md) for the changes in each release.

It supports the following output formats:

* default: plain Databricks/Apache Spark SQL queries
* dbsql: Databricks SQL queries with rules metadata (title, status) embedded as comment
* detection_yaml: Yaml markup for my own detection framework
* lakewatch: Lakewatch detection rules (Unity Catalog governed), batch by default

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

Generate [Lakewatch](https://www.databricks.com/product/lakewatch) detection rules from Sigma rules
(see the [Lakewatch documentation](https://docs.databricks.com/aws/en/lakewatch/)). Each rule is a
Unity Catalog governed resource. By default, rules are converted against the tables of Lakewatch
parsers (see [Lakewatch parsed tables](#lakewatch-parsed-tables)). Converting against OCSF gold
tables is optional (see [OCSF (optional)](#ocsf-optional)).
To deploy the converted rules, see [Deploying rules](#deploying-rules).

```bash
sigma convert -s -t databricks -f lakewatch -O parsers=aws_cloudtrail \
  -O table_name=main.sec.aws_cloudtrail -O catalog_name=main -O schema_name=sec \
  -O warehouse_id=1234567890abcdef rules/ -o detections.yaml
```

Multiple rules are emitted as separate `---` documents in one file. To write one file per rule
instead, pass `-O output_dir=<dir>` (see the `output_dir` option under
[Lakewatch parsed tables](#lakewatch-parsed-tables)).

### Options (`-O key=value`)

| Option | Default | Meaning |
|--------|---------|---------|
| `table_name` | *(none)* | FROM table. For parsed tables see the `table_name` and `table_map` options under [Lakewatch parsed tables](#lakewatch-parsed-tables); in OCSF mode it's derived from the OCSF class if unset (see [OCSF (optional)](#ocsf-optional)). |
| `schedule` | `24h` | Rule schedule (Lakewatch duration). |
| `default_fidelity` | *(from status)* | Override the rule fidelity. Accepts both `Investigative` and `FIDELITY_INVESTIGATIVE`. |
| `default_category` | `Static Signature` | Rule category. |
| `catalog_name` | *(required)* | `catalog_name` of the rule, also used as `batch.sql.default_catalog_name` to resolve unqualified tables. Conversion fails if unset or empty. |
| `schema_name` | *(required)* | `schema_name` of the rule, also used as `batch.sql.default_schema_name`. Conversion fails if unset or empty. |
| `warehouse_id` | *(none)* | `batch.warehouse_id`: SQL warehouse that runs the rule. The server rejects enabled batch rules without one, so conversion warns if it's unset. |
| `extend_lookback` | *(none)* | `timerange.extend_lookback`: widens the time window beyond the schedule. |
| `enabled` | `false` | `schedule.enabled`. Converted rules are disabled by default so that they can be reviewed and tested first; set `-O enabled=true` to schedule them immediately. |

Only batch rules are generated (streaming is future work). Sigma metadata maps to Lakewatch as
follows:

* `title`→`output.summary`, `description`→`description`/`objective`, `level`→`severity`, and `attack.*` tags→`mitre`.
* The SQL filters on `IN_TIMERANGE(time)`, which follows the schedule.
* `rule_name` is derived from the title in snake_case (e.g. `Encoded PowerShell` →
  `encoded_powershell`). Duplicate names within one output get `_2`, `_3`, … suffixes.
* Up to three Sigma `references` (each up to 512 characters) are emitted as `references`.
* Fidelity values use the enum names. Converted rules haven't been tested against your data, so
  Sigma `stable` maps to `FIDELITY_INVESTIGATIVE` and every other status to `FIDELITY_DEVELOPMENT`.
  `default_fidelity` overrides this.
* Rules are emitted with `schedule.enabled: false` (see the `enabled` option).
* `output.event_time_column` is `time`.
* `description` is cut to 4096 characters and `objective` to 65536. Cut values end with `...`.
* Sigma `falsepositives` become the `runbook` ("Known false positives: …", up to 4096 characters).
* `annotations` record where the rule came from: `sigma_id`, `sigma_status`, `sigma_author`,
  `sigma_tags` (tags other than ATT&CK) and `converter_version`. Values are cut to 256 characters,
  and empty values are left out. Content-pack documents have no `converter_version`, so a new
  converter release doesn't change the content hash of every rule in a pack.

### Lakewatch parsed tables

By default, `-f lakewatch` converts rules against the columns of a Lakewatch parser's table.
`-O parsers=...` selects the parsers. To convert against OCSF gold tables instead, see
[OCSF (optional)](#ocsf-optional).

```bash
sigma convert -s -t databricks -f lakewatch -O parsers=aws_cloudtrail \
  -O table_name=main.sec.aws_cloudtrail -O catalog_name=main -O schema_name=sec \
  -O warehouse_id=1234567890abcdef rules/ -o detections.yaml
```

Each selected parser produces one rule per Sigma rule, named `<rule_name>__<profile>`, with
`sigma_profile: <id>@<version>` in its annotations. Options:

| Option | Default | Meaning |
|--------|---------|---------|
| `parsers` | *(none)* | Comma-separated profile ids, for example `aws_cloudtrail,okta_system_log`. Without it, no rules are converted: parser discovery runs and reports which profiles can convert the rules (see [Parser discovery](#parser-discovery)). |
| `table_name` | *(none)* | Table to read from. Use it when exactly one parser is selected. |
| `table_map` | *(none)* | `profile:table,profile:table` for several parsers. Every selected profile needs a table. |
| `lakewatch_profiles_dir` | *(none)* | Directory with your own `*.yml` profiles. They are added to the built-in ones, and an id replaces a built-in id. |
| `lakewatch_schemas` | *(none)* | JSON file with additional parser schemas, in the format of the bundled catalog. |
| `output_dir` | *(none)* | Write one `<rule_name>.yaml` file per rule into this directory (created if missing) instead of one multi-document YAML file. With `target=content_pack` it's the pack's `rules/` directory (see [Content-pack output](#content-pack-output)). It also receives `conversion_report.yaml` (see [Conversion report](#conversion-report)). |
| `target` | `workspace` | `workspace` creates rules for the Lakewatch API. `content_pack` creates the rule documents of a Lakewatch content pack (see [Target modes](#target-modes)). |
| `overrides` | *(none)* | YAML file with per-rule `summary`, `context` and `select` settings, keyed by Sigma id (see [Alert summaries](#alert-summaries)). |

By default all rules go into one multi-document YAML file (`-o file.yaml`, or stdout). With
`-O output_dir=<dir>` each rule is written to its own `<dir>/<rule_name>.yaml`, and only a
one-line summary is printed. Files with the same name are overwritten, and other files in the
directory are left as they are. `output_dir` works only with the `lakewatch` format. Don't use the
`--output-dir`/`-od` option of sigma-cli with Lakewatch formats: it writes only the bare SQL condition
of each rule, not the rule documents.

A profile maps Sigma fields to columns and paths of a parser's schema. Profiles are validated
against the schema catalog when conversion starts, before any rule is converted, so an unknown
path or a bad prefix mapping stops the run. This user profile, saved in a directory passed as
`-O lakewatch_profiles_dir=...`, extends the `aws_cloudtrail` parser. A parser that isn't in the
bundled catalog also needs `-O lakewatch_schemas=<file>` with its schema.

```yaml
profile: my_cloudtrail
version: 1
parser: aws_cloudtrail
fields:
  eventName: eventName                       # exact mapping to a column
  userIdentity.type: userIdentity.type       # path inside a VARIANT column
  requestParameters.*: requestParameters.*   # prefix mapping, free-form VARIANT only
  Principal: [userIdentity.arn, userIdentity.principalId]  # several targets are ORed
entity: userIdentity.arn                    # alert grouping key, selected as sigma_entity
logsources:
  - match: {product: aws, service: cloudtrail}   # product, category and service
    conditions:
      eventType: AwsApiCall                 # added to every rule with this logsource
    unsupported: [Destination]              # fail with a clear message
```

`entity` is a schema path (a column or a nested path, no arrays) or an SQL expression, for example
`coalesce(nullif(ComputerName, ''), aid)`. An identifier-like value must be a schema path; anything
else is SQL used verbatim. Every query selects it as `sigma_entity`, and the
default alert summary groups alerts by it (see [Alert summaries](#alert-summaries)). All built-in
profiles have an `entity`.

VARIANT paths render as `try_variant_get(col, '$.path', 'type')`, and paths through arrays as
`exists(col, x0 -> ...)`.

An array inside a VARIANT column matches the same way, but only when the parser schema declares the
array. The target is then the leaf path without a `[]` marker, and a rule matches when any element
matches. It renders as
`exists(try_variant_get(col, '$.path', 'ARRAY<VARIANT>'), x0 -> ...)`, or with `'ARRAY<<elem>>'`
when the elements are scalars. An array the schema doesn't declare gets no such rendering.

Windows event fields are often a list of `{_Name, _VALUE}` entries, for example the `EventData`
column of the Windows parsers. A target `EventData[Image]` reads the `_VALUE` of the entry whose
`_Name` is `Image`. It works on a VARIANT column (cast to `ARRAY<STRUCT<_Name, _VALUE>>`) and on
a top-level `ARRAY<STRUCT>` column with `_Name` and `_VALUE` members, and the value is a STRING:

```yaml
fields:
  Image: EventData[Image]
  # renders as try_element_at(filter(try_variant_get(EventData, '$',
  #   'ARRAY<STRUCT<_Name: STRING, _VALUE: STRING>>'), e -> e._Name = 'Image'), 1)._VALUE
```

Other logs use the same shape with other member names. The profile key `entries` declares, per
column, the members and options of the named entries:

```yaml
entries:
  httpRequest.headers: {name: name, value: value, ignore_case: true}   # one-level array in a VARIANT
  parameters: {name: name, value: [value, boolValue]}                  # top-level VARIANT
fields:
  cs-user-agent: httpRequest.headers[User-Agent]
  setting_name: parameters[SETTING_NAME]
```

* `name` is the member that holds the entry name, and `value` the member that holds the value. `value`
  may be a list, and then the first member that is set is used, with every member read as a string
  (so `boolValue` renders as `'true'` or `'false'`).
* `ignore_case: true` compares the entry name case-insensitively, for example for HTTP headers.
* `entries` works on a top-level VARIANT column, on a top-level `ARRAY<STRUCT>` column, and on a
  declared array one level inside a VARIANT. `[*]` isn't supported on a declared column. A
  declared VARIANT array has no single-object fallback, unlike an undeclared VARIANT column.
* A column without an `entries` key uses `_Name` and `_VALUE`. A target with `[Name]` also works
  for `entity`.

#### Parser discovery

If you don't know which parsers fit your rules, leave out `-O parsers`. With `-f lakewatch` in
parsed mode (no `-O ocsf=true`, no `-p ocsf`) and no `parsers`, the backend converts nothing.
It tries every loaded profile (built-in and from `lakewatch_profiles_dir`) on each rule and
prints a report on stdout. It needs no `catalog_name`, `schema_name` or table options, and it
writes no files, even with `output_dir`. A warning on stderr says so:

```bash
sigma convert -t databricks -f lakewatch rules/windows/proc_creation_encoded_ps.yml
```

```text
UserWarning: no rules were converted: -O parsers=... was not given, so parser discovery ran instead (report on stdout)
rules:
- sigma_id: 5f1b9c8e-1111-4222-8333-444455556666
  title: Encoded PowerShell
  logsource:
    product: windows
    category: process_creation
    service: null
  convertible:
  - carbonblack_endpoint_event
  - crowdstrike_fdr_event
  - sentinelone_deep_visibility
  - windows_security_process
  - windows_sysmon_process
  not_convertible: {}
summary:
  rules: 1
  convertible_rules:
    carbonblack_endpoint_event: 1
    ...
  failure_reasons: {}
  suggested_option: -O parsers=carbonblack_endpoint_event,crowdstrike_fdr_event,sentinelone_deep_visibility,windows_security_process,windows_sysmon_process
```

* Only the profiles whose `logsources` block matches the rule's logsource and routes it are
  tried. A profile is `convertible` when the rule converts without an error and with a non-empty
  query. Otherwise it's listed in `not_convertible` with the reason.
* A rule with no matching profile gets `note: no profile matches the logsource`. A correlation
  rule gets `note: correlation rules are not supported`. A base rule that a correlation rule
  references gets `note: referenced by a correlation rule`. A rule with Sigma status `deprecated`
  or `unsupported` gets `note: status <status> (would be skipped)`: its lists still show, but it
  counts toward neither `convertible_rules` nor `suggested_option`.
* `summary.convertible_rules` counts the rules per profile. `failure_reasons` has the most
  frequent reasons (up to 20). `suggested_option` is a `-O parsers=...` value with every profile
  that can convert at least one rule, or `null` if none can. Pick the parsers that match the
  data you have: the suggestion lists every profile that fits, not the ones you ingest.
* Python API: `DatabricksBackend.discover_parsers(rules)` returns the same structure as a dict.
  It leaves `errors` and the other backend state as they were.

Calling `convert_rule` directly without `parsers` is still a configuration error.

#### Conversion report

With `-O output_dir=<dir>`, a conversion also writes `<dir>/conversion_report.yaml` in both
targets. With `target=content_pack` it sits in the pack's `rules/` directory next to
`revisions.yaml`. Don't commit it to the pack. Without `output_dir`, stdout stays the
multi-document YAML and no report is written. The report never fails a conversion that would
otherwise succeed. With `-s` it also lists failed rules. Without `-s`, the first error aborts the
run and no report is written.

```bash
sigma convert -s -t databricks -f lakewatch \
  -O parsers=windows_sysmon_process,windows_security_process \
  -O table_map=windows_sysmon_process:main.sec.sysmon,windows_security_process:main.sec.winsec \
  -O catalog_name=main -O schema_name=sec -O output_dir=out rules/windows/
```

```yaml
summary:
  rules: 2
  converted: 1
  failed: 0
  skipped: 1
  by_logsource:
    windows/process_creation/-:
      converted: 1
      failed: 0
      skipped: 1
rules:
- sigma_id: 5f1b9c8e-1111-4222-8333-444455556666
  title: Encoded PowerShell
  source: rules/windows/pc.yml
  logsource: {product: windows, category: process_creation, service: null}
  status: converted
  reason: null
  results:
  - profile: windows_security_process@1
    status: converted
    rule_names: [encoded_powershell__windows_security_process]
    reason: null
    approximate: false
    fields:
      Image:
        targets: ["EventData[NewProcessName]"]
        resolution: mapped
      CommandLine:
        targets: ["EventData[CommandLine]"]
        resolution: event_data
    warnings: []
    lint: []
- sigma_id: 6f1b9c8e-1111-4222-8333-444455556666
  title: Old Rule
  status: skipped
  reason: status deprecated
  # ...
```

* **`summary`**: input rule counts (correlation rules included) and the same counts per logsource,
  keyed `<product>/<category>/<service>` with `-` for an unset part.
* **`rules`**: one entry per input rule, in input order. `source` is the rule's file, or `null`.
  `status` is `converted` if any result converted. Otherwise it's `skipped` (Sigma status
  `deprecated` or `unsupported`, or every query empty: the reasons are `status deprecated`,
  `status unsupported` and `empty query`), or else `failed` with the error text as `reason`. A
  base rule that only a correlation rule references makes no query of its own: it is `skipped`
  with reason `referenced by a correlation rule`. A correlation rule (with `-s`) is reported as
  `failed` with the reason `correlation rules not supported by the lakewatch format (rule '<title>')`
  and a `null` logsource.
* **`results`**: one per selected profile, in conversion order (`profile` is `null` in OCSF mode).
  `rule_names` are the final names after de-duplication.
* **`fields`**: for each field of the rule's detection items, in first-use order, the profile
  `targets` and how the field was resolved. `resolution` is one of:
  * `mapped`: an explicit `fields` mapping of the profile or the logsource block;
  * `event_data`: a name from an `event_data` list;
  * `prefix`: a prefix mapping;
  * `lenient`: `event_data: any`, read as `<event_data_column>[<field>]`;
  * `unmapped`: none of the above (`targets` is empty).

  In OCSF mode `fields` is `{}`.
* **`warnings`**: the warnings that were shown while the result converted, as strings. Warnings
  hidden by a Python warning filter (or by its once-per-location dedup) are not listed. They are
  still printed on stderr as usual.
* **`approximate`**: `true` if the match is approximate: the raw keyword search, or a text match
  on the JSON of a VARIANT. It is set even when the warning itself is filtered out. Review such rules before enabling them.
* **`lint`**: hints that don't fail the rule. For a `lenient` field whose name matches a top-level
  column of the parser, ignoring case: `field <F> is read from <col>[<F>] by event_data any, but <Column> is a top-level column of parser <parser>; map it explicitly`.

In Python, `backend.last_report` holds the report of the last `lakewatch` conversion, in the same
structure as the file (`None` before the first one, after a discovery run, and after a run that aborted with an error). `write_report` in
`sigma.backends.databricks.lakewatch_report` writes it.

#### Target modes

`-O target=workspace` (the default) creates flat rules for the Lakewatch API. A missing `target`
means `workspace`. `-O target=content_pack` creates the rule documents of a Lakewatch content
pack. It works only with parsed tables, not with OCSF mode. Both modes read the same Sigma rules.

Abbreviated `workspace` document:

```yaml
catalog_name: main
schema_name: sec
rule_name: encoded_powershell__windows_sysmon_process
description: ...
schedule:
  at_least_every: 24h
  enabled: false
batch:
  warehouse_id: 1234567890abcdef
  sql:
    query: |-
      SELECT *, Computer AS sigma_entity
      FROM main.sec.windows_sysmon_process
      WHERE IN_TIMERANGE(time) AND (...)
    default_catalog_name: main
    default_schema_name: sec
output:
  summary: Encoded PowerShell on {sigma_entity}
  event_time_column: time
  default_context: true
```

Abbreviated `content_pack` document:

```yaml
description: ...
metadata:
  rule_kind: panther
  displayName: Encoded PowerShell
  table_parameters:
    events:
      display_name: Events
      parser_ids: [<uuid of the parser>]
rule:
  rule_name: encoded_powershell__windows_sysmon_process
  content_resource_id: <uuid>
  schedule:
    at_least_every: 24h
  batch:
    sql:
      query: |-
        SELECT *, Computer AS sigma_entity
        FROM {{table.events}}
        WHERE IN_TIMERANGE(time) AND (...)
  output:
    summary: Encoded PowerShell on {sigma_entity}
    event_time_column: time
    default_context: true
```

In `content_pack` mode:

* The rule has no `catalog_name` or `schema_name`. The query reads `{{table.events}}`, which the
  pack binds to the parser's table, and `schedule` has no `enabled`.
* `content_resource_id` is derived from the lower-case Sigma id and the profile id
  (`<sigma id>:<profile>`), so converting the same rule again gives the same id. It's a UUIDv4,
  as the content marketplace requires: the bytes of the UUIDv5 of that name, with the version
  bits set to 4. The rule must
  have an `id`.
* `metadata.table_parameters.events.parser_ids` holds the `uuid` of the parser's entry in the
  schema catalog. The built-in parsers have one, but the Windows parsers of the bundled
  `windows_custom` catalog (for example `windows_sysmon_process`) don't. For a parser without one,
  conversion fails with a configuration error that tells you to add `"uuid"` to its entry in a
  `-O lakewatch_schemas=<file>` file.
* `catalog_name`, `schema_name`, `warehouse_id`, `table_name`, `table_map` and `enabled` are
  ignored, with one warning.

#### Alert summaries

The `output.summary` of a rule is a template. Lakewatch fills each `{column}` from the alert's
rows. The backend picks the summary like this:

1. A summary from the overrides (below), if there is one.
2. `"<title> on {sigma_entity}"`, if the profile has an `entity`. Braces in the title become
   parentheses, because Lakewatch reads `{...}` as a placeholder.
3. The title alone, if the profile has no `entity`. The conversion warns that all signals of the
   rule group into one alert.

A rule can set `summary`, `context` and `select` with the `lakewatch:` attribute, a top-level key
of the Sigma rule. This example targets the `windows_sysmon_process` profile:

```yaml
title: Suspicious PowerShell
id: 5f1b9c8e-3c1a-4f0e-9a43-1d2e3f4a5b6c
# logsource, detection, ...
lakewatch:
  summary: "PowerShell by {sigma_user} on {sigma_entity}"
  context:
    command: "{sigma_cmd}"
  select:
    sigma_user: User              # a Sigma field of the profile
    sigma_cmd: CommandLine
    parent: ParentImage
    host_upper: "upper(Computer)"    # anything else is raw SQL
```

`-O overrides=<file>` takes the same keys from a YAML file keyed by Sigma id. An id maps either
directly to the keys, or to `default` and profile ids:

```yaml
5f1b9c8e-3c1a-4f0e-9a43-1d2e3f4a5b6c:        # flat: all profiles
  summary: "PowerShell by {sigma_user} on {sigma_entity}"
  select:
    sigma_user: User
a1b2c3d4-0000-4000-8000-000000000001:        # per profile
  default:
    summary: "{sigma_entity}: suspicious process"
  crowdstrike_fdr_event:
    select:
      sigma_user: event.UserName
```

Mixing the keys with profile ids in one entry is an error.

A flat entry applies to every selected profile, so its `select` values must resolve on each one
(`sigma_user: User` fails on `crowdstrike_fdr_event`, which has no `User` field). Scope the entry per
profile otherwise.

* **Precedence** applies per key. For each of `summary`, `context` and `select`, the first of these
  that sets the key wins: the file's entry for the profile, the file's `default` entry, the rule
  attribute. So an override file can replace the summary of a rule and still use its `select`.
* **`select`** maps an alias to a value. A value that is a Sigma field or a schema path is resolved
  through the profile, and anything else is used as raw SQL. Each entry becomes
  `<expr> AS <alias>` in the SELECT list, after `*` and `sigma_entity`. An alias must be a bare
  identifier that doesn't clash with a column of the parser or `sigma_entity`. A field that maps
  to several targets, uses a transform or sits inside an array fails the rule: use an SQL
  expression for it.
* **Placeholders.** Each `{x}` in `summary` and in the `context` values must name an output column:
  a top-level column of the parser's schema, a `select` alias or `sigma_entity`. Anything else
  fails the rule with `placeholder {x} is not an output column of profile ...; add it under select`.
* **`context`** maps names to templates and is written as `output.context`. A rule with a `context`
  has `default_context: false`.
* The file is read by Sigma id (case-insensitive). Conversion warns about ids in the file that no
  converted rule has, and about profile keys that aren't a loaded profile. `overrides` applies to
  parsed-table mode only. In OCSF mode it's ignored, with a warning.

#### Content-pack output

For `-O target=content_pack`, point `output_dir` at the `rules/` directory of a content pack:

```bash
sigma convert -s -t databricks -f lakewatch -O target=content_pack \
  -O parsers=windows_sysmon_process -O lakewatch_schemas=schemas.json \
  -O output_dir=my_pack/rules rules/windows/
```

It writes:

```text
my_pack/rules/
  encoded_powershell__windows_sysmon_process/
    encoded_powershell__windows_sysmon_process.yaml   one rule document
  revisions.yaml                                      content hashes and versions
  appIndex.rules.yaml                                 fragment for appIndex.yaml
```

* **`revisions.yaml`** has an entry per rule: `name`, `latestVersion` and `contentHash`, the
  sha256 of the rule file. A new rule is added with `latestVersion: 1`. When the hash of a rule
  changes, `latestVersion` goes up by one and the entry's `versionNote` is dropped. Unchanged
  entries stay byte-identical, as do comments, ordering and the entries of rules that weren't
  converted in this run. The file is edited as text, not re-serialized, so your formatting stays.
  A layout the merge doesn't support (for example a flow-style list) stops the run with a
  configuration error and writes nothing (no rule files either), rather than guessing.
* **`appIndex.rules.yaml`** is a fragment that lists every rule directory in `output_dir`, sorted:
  `rules: [{name: <rule>}, ...]` (written as a block list of `- name: <rule>`). The backend doesn't touch `appIndex.yaml`. Paste the fragment into it.

Field mapping is strict. A Sigma field that isn't a key of the profile's `fields` fails that
rule with `field <name> is not mapped by profile <id>`, and keyword (unbound) searches fail as
well. Use `-s` to skip failed rules when converting a directory.

#### Value transforms

A mapping can rewrite the Sigma values before they are compared. Transforms come from a fixed
library and are configured in the profile:

| Transform | Parameters | What it does |
|-----------|------------|--------------|
| `map` | `values: {from: to \| [to, ...]}`, `default: keep \| fail` (`fail`) | Replaces a value; a list becomes an OR. Keys are case-insensitive. |
| `case` | `upper` or `lower` | Changes the case of string values. |
| `basename` | none, or optional `also_suffix: true \| false` (`false`) | Keeps the last path component: `C:\dir\cmd.exe` and `*\cmd.exe` become `cmd.exe`, and `*cmd.exe` is kept. Fails for patterns on the directory, such as `startswith`, or `contains` without a separator (`*Microsoft Office*`). With `also_suffix: true`, the column can hold a base name or a full path. Each base name `N` matches `N` exactly or ends with `\N`. Values without a separator count as base names too, including ones with an inner wildcard (`cmd.exe`, `py*.exe`, `?md.exe`). A value that used `/` (`/usr/bin/bash`) also matches a value ending with `/N`. A value starting with `*` and no separator (`*cmd.exe`) already matches both forms, so it stays as is. |
| `path_prefix` | `rewrite: [{from: <regex>, to: <prefix>}]`, optional `keep_original: true \| false` (`false`) | Rewrites the start of a path, for example `C:` to `\Device\HarddiskVolume*`. With `keep_original`, a rewritten value matches the original or the rewritten form. Fails when a `from` match follows a leading wildcard (`*C:\...`). |
| `registry_path` | `hive: short \| long \| kernel`, optional `split: {key: <path>, value: <path>}` | Normalizes the hive name (`HKLM`, `HKEY_LOCAL_MACHINE`, `\REGISTRY\MACHINE`, ...) at the start of a value. Fails when a hive follows a leading wildcard (`*HKLM\SOFTWARE\...`). With `split`, see below. |
| `hashes` | `algos: {MD5: <path>, SHA1: <path>, SHA256: <path>, IMPHASH: <path>}` | Routes `ALGO=digest` values (or a bare digest, by its length) to the column of the algorithm. |
| `domain_user` | `{domain: <path>, user: <path>}` | Matches `DOMAIN\user` values, see below. |
| `regex_replace` | `pattern`, `replacement` | Regex substitution on the literal parts of a string. |
| `to_hex` | none, or optional `prefix: <str>` (`0x`) | Turns an exact decimal number into lowercase hex with the prefix (`4120` becomes `0x1018`). Fails for wildcards, negative numbers, ordering comparisons and regular expressions. |
| `first_set` | `candidates: [<path> \| {domain: <path>, user: <path>}, ...]` (at least 2), optional `unset: [<str>]` (`['-']`) | Matches the first candidate that is set (not NULL, empty or in `unset`), rendered as a `CASE WHEN` expression; the condition applies to it unchanged. A `{domain, user}` candidate is the joined `DOMAIN\user`. Must be the last transform; field references to it fail. |
| `join` | `sep: <str>` (non-empty), `parts: [<path>, <path>]` (exactly 2 scalar columns) | Matches the two parts joined with `sep`, rendered as `concat_ws(sep, nullif(a, ''), nullif(b, ''))`, so an empty or missing part leaves the other alone with no separator. Every modifier sees the joined value, and a value may match across the separator. `null` fails to convert. |
| `to_int`, `to_str` | none | Converts digit strings to numbers, or numbers and booleans to strings. |
| `reject` | `pattern: <regex>`, `reason: <text>` | Fails the rule with `reason` when a value matches `pattern` (`re.search`, case-insensitive), for values the target column never holds. Wildcards are matched as `*` and `?`; a regex value is checked on its text without a leading `^` and backslash escapes. |

```yaml
transforms:                                  # named transforms, usable in every block
  reg: {registry_path: {hive: long, split: {key: RegistryKey, value: RegistryValueName}}}
fields:
  Protocol: {field: proto, transform: {map: {values: {tcp: 6, udp: 17}}}}
  ParentImage: {field: ParentBaseFileName, transform: basename, modifiers: [eq, endswith]}
  CommandLine: {field: cmd, transform: [{case: lower}, {regex_replace: {pattern: '\s+', replacement: ' '}}]}
  TargetObject: {transform: reg}             # targets come from the transform
  Hashes: {transform: {hashes: {algos: {SHA256: SHA256, MD5: MD5}}}}
  Initiated:
    select_condition:                        # the value picks conditions instead of a predicate
      'true': {event_type: NetworkConnect}
      'false': {event_type: NetworkAccept}
  CustomField: {field: userIdentity.customKey, undeclared: true}
```

* A transform that can't keep the meaning of a value fails the rule with
  `field <F>: transform <kind>: <reason> (profile <id>)`. A condition is never dropped silently,
  except hash algorithms the profile doesn't have, which are dropped with a warning. With `|all`,
  or when no value is left, the rule fails instead.
* `null` and `|exists` checks pass value transforms unchanged. `hashes`, `domain_user` and
  `registry_path` with `split` fail on them, because they choose the target from the value.
* Transforms run on the values after the Sigma modifiers, wildcards included. Field references
  (`|fieldref`) to or from a transformed field aren't supported.
* `registry_path` with `split` and `domain_user` compare the value with the joined expression
  `concat_ws('\\', nullif(<key>, ''), nullif(<value>, ''))`, so every modifier keeps its meaning.
  An empty value name (the key's default value) or a missing domain gives the other part alone.
  A value ending with `\(Default)` fails the rule, because the joined columns never hold that
  name.
* `select_condition` maps each value (case-insensitive; `true`/`false` for booleans) to
  conditions that are ANDed. Several values are ORed, and `not` works as usual. Another value,
  or a wildcard, fails the rule. When the rule doesn't use the field, only the block conditions
  apply. Negating a value whose selection equals the block's own conditions gives a rule that
  can't match, for example `not Initiated: 'true'` on an outbound-only profile.
* Fields with a transform or `select_condition` don't support `|cased`: the rule fails with
  `field <F>: case-sensitive matching is not supported`. Expanded values (`|windash`,
  `|base64offset`) on transformed fields fail as well.
* `modifiers` lists the Sigma modifiers allowed on a field (`eq` for none). Any other modifier
  fails the rule with `field <F>: modifier <m> is not supported`. Unless a comparison modifier
  (`contains`, `startswith`, `endswith`, `re`, `cidr`, `gt`, `gte`, `lt`, `lte`, `exists`, `fieldref`)
  is present, the comparison is an equality, so the field must allow `eq` as well. For example,
  `c-uri|all: [...]` needs both `eq` and `all` in the list, and fails otherwise, while
  `c-uri|contains|all` needs only `contains` and `all`.
* `undeclared: true` allows a target inside a VARIANT column that declares sub-fields, but not
  this one: a key that the data has and the parser schema doesn't list. It is extracted as a
  string.
* The top-level `products` map adds conditions per Sigma product, for example
  `products: {windows: {event_platform: Win}}`. Block conditions win on the same field. With
  `products` set, a rule whose product isn't listed doesn't match the profile.

Current limitations:

* Keyword (unbound) searches aren't supported yet.
* Comparisons against a whole VARIANT column: `|contains` is matched approximately against the
  JSON text, with a warning; other comparisons fail. Use a path such as
  `requestParameters.bucketName` for exact matching.
* Rules that use these fail. With `sigma convert -s` they are skipped and reported.

Writing profiles: `scripts/scaffold_profile.py PARSER --match product=windows,category=process_creation --rules <sigma rules dir>`
writes a starting profile with one identity line per schema path, a `# used by N rules` comment
on each path that matching rules use, and a trailing list of Sigma fields the schema lacks. Use
`--schemas` for a schema file that isn't built in. To build such a file from a table, run
`scripts/describe_to_schema.py --parser NAME -o out.json` with either `--describe-json FILE` (the
output of `DESCRIBE TABLE EXTENDED <table> AS JSON`) or `--table c.s.t --profile P --warehouse-id W`,
which runs the statement through the `databricks` CLI. `--profile` is never defaulted.

Built-in profiles:

| Profile | Logsource | Parser |
|---------|-----------|--------|
| `aws_cloudtrail` | `product: aws`, `service: cloudtrail` | `aws_cloudtrail` |
| `okta_system_log` | `product: okta`, `service: okta` | `okta_system_log` |
| `azure_audit` | `product: azure`, `service: auditlogs` | `azure_audit` |
| `azure_signin` | `product: azure`, `service: signinlogs` | `azure_signin` |
| `azure_monitor_activity` | `product: azure`, `service: activitylogs` | `azure_monitor_activity` |
| `azure_identity_protection` | `product: azure`, `service: riskdetection` | `azure_identity_protection` |
| `microsoft365_audit_general` | `product: m365`, `service: audit` | `microsoft365_audit_general` |
| `microsoft365_audit_azure_active_directory` | `product: m365`, `service: audit` | `microsoft365_audit_azure_active_directory` |
| `microsoft365_audit_exchange` | `product: m365`, `service: audit` or `exchange` | `microsoft365_audit_exchange` |
| `gcp_audit_log` | `product: gcp`, `service: gcp.audit` | `gcp_audit_log` |
| `google_workspace_reports` | `product: gcp`, `service: google_workspace.admin` or `google_workspace.login` | `google_workspace_reports` |
| `cloudflare_http_request` | `category: webserver` | `cloudflare_http_request` |
| `gcp_http_load_balancer` | `category: webserver` | `gcp_http_load_balancer` |
| `akamai_waf` | `category: webserver` | `akamai_waf` |
| `aws_waf_web_acl` | `category: webserver` | `aws_waf_web_acl` |
| `zscaler_zia_web_log` | `category: proxy` | `zscaler_zia_web_log` |
| `ciscoumbrella_proxy` | `category: proxy` | `ciscoumbrella_proxy` |
| `crowdstrike_fdr_event` | `product: windows`, `linux` or `macos` with `category: process_creation`; `product: windows` with `category: network_connection`, `dns_query`, `file_event` or `registry_set` | `crowdstrike_fdr_event` |
| `sentinelone_deep_visibility` | `product: windows`, `linux` or `macos` with `category: process_creation`, `file_event`, `file_change`, `file_rename`, `file_delete`, `image_load`, `registry_set`, `dns_query`, `dns`, `network_connection` or `firewall` | `sentinelone_deep_visibility` |
| `carbonblack_endpoint_event` | `product: windows`, `linux` or `macos` with `category: process_creation`, `file_event` or `network_connection` | `carbonblack_endpoint_event` |
| `windows_sysmon_process` | `product: windows` with `category: process_creation`, `process_termination`, `driver_load`, `image_load`, `create_remote_thread`, `raw_access_thread`, `process_access` or `process_tampering`; `service: sysmon` (EventIDs 1, 5-10, 25) | `windows_sysmon_process` (requires the custom Windows parsers) |
| `windows_sysmon_network` | `product: windows` with `category: network_connection`; `service: sysmon` (EventID 3) | `windows_sysmon_network` (requires the custom Windows parsers) |
| `windows_sysmon_dns` | `product: windows` with `category: dns_query`; `service: sysmon` (EventID 22) | `windows_sysmon_dns` (requires the custom Windows parsers) |
| `windows_sysmon_file` | `product: windows` with `category: file_change`, `file_event`, `create_stream_hash`, `file_delete`, `file_block_executable`, `file_block_shredding` or `file_executable_detected`; `service: sysmon` | `windows_sysmon_file` (requires the custom Windows parsers) |
| `windows_sysmon_registry` | `product: windows` with `category: registry_add`, `registry_delete`, `registry_set`, `registry_rename` or `registry_event`; `service: sysmon` (EventIDs 12-14) | `windows_sysmon_registry` (requires the custom Windows parsers) |
| `windows_sysmon_other` | `product: windows` with `category: sysmon_status`, `pipe_created`, `wmi_event`, `clipboard_capture` or `sysmon_error`; `service: sysmon` for any EventID not served by the other five | `windows_sysmon_other` (requires the custom Windows parsers) |
| `windows_security_process` | `product: windows` with `category: process_creation` (EventID 4688); `service: security` (EventIDs 4688, 4689, 4690, 4696) | `windows_security_process` (requires the custom Windows parsers) |
| `windows_security_authentication` | `product: windows`, `service: security` (EventIDs 4624, 4625, 4627, 4634, 4647, 4648, 4768-4772, 4776-4779, 4800, 4801) | `windows_security_authentication` (requires the custom Windows parsers) |
| `windows_security_account_change` | `product: windows`, `service: security` (EventIDs 4720, 4722-4726, 4738, 4740-4742, 4767, 4780, 4781, 4794, 4798) | `windows_security_account_change` (requires the custom Windows parsers) |
| `windows_security_group_management` | `product: windows`, `service: security` (EventIDs 4727-4735, 4737, 4754-4758, 4764, 4799) | `windows_security_group_management` (requires the custom Windows parsers) |
| `windows_security_user_access` | `product: windows`, `service: security` (EventIDs 4672-4674, 4703-4705, 4717, 4718) | `windows_security_user_access` (requires the custom Windows parsers) |
| `windows_security_network` | `product: windows`, `service: security` (EventIDs 5140, 5145, 5152, 5156-5159) | `windows_security_network` (requires the custom Windows parsers) |
| `windows_security_other` | `product: windows`, `service: security` for any EventID not served by the other six; EventData fields are mapped leniently with a warning | `windows_security_other` (requires the custom Windows parsers) |
| `windows_powershell_script` | `product: windows` with `category: ps_script` (4104) or `ps_module` (4103); `service: powershell` (EventIDs 4103-4106) | `windows_powershell_script` (requires the custom Windows parsers) |
| `windows_powershell_other` | `product: windows`, `service: powershell` for any EventID other than 4103-4106 | `windows_powershell_other` (requires the custom Windows parsers) |
| `windows_system`, `windows_application`, `windows_taskscheduler`, `windows_defender_detection`, `windows_wmi_activity`, `windows_ntlm_authentication`, `windows_applocker` | `product: windows` with `service: system`, `application`, `taskscheduler`, `windefend`, `wmi`, `ntlm`, `applocker` | the profile of the same name (requires the custom Windows parsers) |
| `windows_event_other` | `product: windows` with `service: codeintegrity-operational`, `appxdeployment-server`, `firewall-as`, `msexchange-management`, `bits-client`, `dns-client`, `iis-configuration`, `security-mitigations` or `dns-server` (matched by `Channel`); classic PowerShell: `category: ps_classic_start`, `ps_classic_provider_start`, `ps_classic_script` or `service: powershell-classic` | `windows_event_other` (requires the custom Windows parsers) |
| `windows_event_logs` | `product: windows` with any of the services above, plus `security` and `powershell` (matched by `Channel`); header columns only | `windows_event_logs` (Lakewatch built-in) |

The Azure profiles convert most SigmaHQ `cloud/azure` rules. PIM alerts (`service: pim`) have no
Lakewatch parser, so they stay unmatched. Sign-in `Status` isn't mapped (the diagnostic `status`
is `{errorCode, additionalDetails}`), `ActivityDetails` doesn't exist, and sign-in
`properties.message` is unsupported (the Graph `signIn` object has no `message`, so it would never match). Array fields
(`targetResources`, `additionalDetails`, `networkLocationDetails`) map to the whole `properties`
column and support only `|contains`, matched approximately against the JSON text. Rules that use
them with any other comparison fail. `contains` searches the whole `properties` JSON, so it can
also match text outside the named array.

The Lakewatch M365 parsers split the unified audit log by workload; a `service: audit` rule converts
for each selected parser that has all its fields, and fails with "not mapped" for the others. Among these
three profiles, `ApplicationId` and `RequestType` exist only on the Azure AD parser, `Directionality` only on
the general parser, and `Parameters` only on the Exchange parser. When several M365 parsers are selected, use
`sigma convert -s` (collect errors); without it, the first profile that lacks a field aborts the rule before
the others are tried. `service: exchange` rules go to the Exchange parser. In the
Exchange profile, `status` maps to `ResultStatus` and only `status: success` is mapped (to `True`, `Succeeded` or
`Success`, ORed), so a rule with any other `status` value, such as `failure`, fails to convert. `OperationProperties`
isn't mapped, so rules that use it fail. The `threat_management` and `threat_detection` rules aren't supported yet,
because they match Security & Compliance alert records, which these parsers don't cover. The mappings follow the
Office 365 Management Activity API schema and haven't been checked against live data.

The GCP profiles map Cloud Audit Logs (`gcp_audit_log`) and the Google Workspace Admin SDK Reports
`activities` resource (`google_workspace_reports`). In `google_workspace_reports`, the service fields
(`eventService` and `protoPayload.serviceName`) go through a value map: `admin.googleapis.com` becomes `admin` and
`login.googleapis.com` becomes `login`, and any other service value fails to convert. In `gcp_audit_log`, the service
name passes through unchanged. Of the `data.protoPayload.*` names, only `data.protoPayload.serviceName`,
`.methodName`, `.logName` and `.resource.type` are mapped (there is no
`data.protoPayload.*` prefix), and any other `data.protoPayload.<x>` fails as not mapped. A trailing `*` in
`gcp.audit.method_name` renders `startswith()`. The declared arrays inside `protoPayload`
(`authorizationInfo`, for example `data.protoPayload.authorizationInfo.permission` and `.granted`) match any
element, rendered as `exists(try_variant_get(...), x0 -> ...)`. In `google_workspace_reports`, `setting_name` and
`new_value` map to the `SETTING_NAME` and `NEW_VALUE` entries of `parameters` through `entries`
(`new_value` takes `value`, or `boolValue` as a string). Workspace rules (`service: google_workspace.*`) route only to `google_workspace_reports`, because the
same events in `gcp_audit_log` sit in an array inside a VARIANT. The SigmaHQ `cloud/gcp` rules go from 0/26 to 25/26
convertible; the one that fails (`gcp_breakglass_container_workload_deployed`) uses keyword searches, and its `logName` values
never equal a full `projects/<p>/logs/...` name.

The web profiles cover the `category: webserver` rules (Cloudflare, GCP load balancer, Akamai and AWS WAF)
and the `category: proxy` rules (Zscaler ZIA and Cisco Umbrella). A rule converts per profile, so use
`sigma convert -s` (collect errors) to get a query for every profile that has all the rule's fields; without it, the
first profile that lacks a field aborts the rule. Keyword searches (a detection with no field) fail on every web
profile, because no raw event is configured to search. The mappings follow the vendors' log field references and
haven't been checked against live data.

- **URI semantics.** `cs-uri-query` (webserver) and `c-uri`/`cs-uri` (proxy) hold the whole URL or URI in SigmaHQ
  rules. Cloudflare maps it to `ClientRequestURI` (path and query), so it behaves as on an access log. GCP maps it to
  `httpRequest.requestUrl` (scheme, host, path and query), Zscaler to `url` (host, path and query, no scheme) and
  Umbrella to `url` (the full URL).
- **U2, whole-URL fields.** On the GCP, Zscaler and Umbrella whole-URL fields, the allowlist is the modifiers
  `contains`, `endswith`, `re` and `all`. Plain equality, `startswith` and a wildcard-only equality such as `'*foo*'`
  fail the rule, because they would silently never match a URL that starts with a scheme or host. `endswith` misses a
  URL with a trailing query string. `all` is allowed in combination with the listed modifiers (`contains|all`,
  `endswith|all`), and `|all` on its own (`c-uri|all: ['/a', '/b']`) fails like plain equality, because `eq` isn't
  in the allowlist (see the `modifiers` rule above). A `|re` anchored at the start (`^/admin`, or `^https?://` on Zscaler, whose `url` has no scheme)
  converts but never matches on a whole URL.
- **Split path and query.** Akamai (`httpMessage.path`, `httpMessage.query`) and AWS WAF (`httpRequest.uri`,
  `httpRequest.args`) store the path and the query in separate columns, so `cs-uri-query` maps through a `join`
  transform: `concat_ws('?', nullif(path, ''), nullif(query, ''))`. Every modifier sees the joined URI, a value with
  a literal `?` matches across both parts (write `\?` in Sigma, since an unescaped `?` is a single-character
  wildcard), and an empty or missing query leaves just the path. `cs-uri-query: null` fails to convert.
- **Unmapped fields.** A field that a log doesn't have fails the rule with `not mapped`: `cs-username` and
  `cs-content-type` on all four webserver profiles; `cs-uri-stem` and `cs-host` on GCP; `cs-user-agent` and `cs-referer` on
  Akamai (they exist only inside the raw `httpMessage.requestHeaders` string); `sc-status` on AWS WAF (it logs only
  the action and the code WAF itself sent); `c-uri-query`, `cs-uri-stem`, `c-uri-extension` and `cs-cookie` on the
  proxy profiles.
- **AWS WAF headers.** `cs-user-agent`, `cs-referer` and `cs-host` map to the `User-Agent`, `Referer` and `Host`
  entries of `httpRequest.headers`, an array inside the `httpRequest` VARIANT, through `entries` with
  `ignore_case: true`. `labels` and `requestHeadersInserted` aren't declared as arrays in the schema, so they map as
  whole columns and support only `|contains`; members such as `labels.name` aren't mapped.
- **Zscaler.** `event` is a VARIANT that holds the vendor event record. Its contents are unverified, so only the
  whole column is mapped, member access isn't, and it is matched only as a whole value with `|contains`.
- **Akamai caveats.** `httpMessage.query` is logged URL-encoded, so values with raw special characters may not
  match, and many SigmaHQ rules list both forms. Akamai logs only requests that triggered a security rule, so rules
  see a subset of the traffic. `httpMessage.status` is a STRING column.
- **Umbrella `hostName`.** `cs-host` maps to `hostName` by decision, but the parser describes it only as "Host name".
  If it is the client host rather than the destination, `cs-host` rules match the wrong thing, and there is no live
  data to confirm it.

The six `windows_sysmon_*` profiles read the Sysmon fields from the `EventData` named entries
(`EventData[Name]`) of the custom Windows parsers (lakewatch parser-generators/windows), which
aren't Lakewatch built-ins yet. Field names come from the Sysmon schema (`sysmon -s`, schema
version 4.90). Values pass through unchanged. A Sigma field that Sysmon doesn't log for the
category (for example `CommandLine` on `file_event`) fails the rule with `field <F> is not mapped
by profile <id>`. `file_access` and `file_rename` rules have no Sysmon event and fail with the
no-profile reason. A rule with `service: sysmon` is routed to the profile that serves its
EventID values, so select all six profiles to cover it.

The seven `windows_security_*` profiles read the Security-channel fields from `EventData[Name]`
entries; field names come from the Microsoft Learn page of each event. A rule with
`service: security` is routed by its EventID values, so select all seven to cover it. Sigma
`process_creation` maps to EventID 4688: `Image` is `NewProcessName`, `ParentImage` is
`ParentProcessName`, process IDs are matched as `0x` hex, `User` and `LogonId` use the target
account when 4688 records one and the creator otherwise, and `IntegrityLevel` maps to the
`MandatoryLabel` SID. A `User` value that matches `AUTHORI`/`AUTORI` fails, because 4688 logs
LocalSystem as the computer account. `Hashes`, `OriginalFileName`, `CurrentDirectory`,
`ParentCommandLine`, `ParentUser`, `Company`, `Description`, `Product` and `FileVersion` fail
the rule as unsupported.

The PowerShell and channel profiles (`windows_powershell_*`, `windows_system` and the other
channel parsers, and `windows_event_other`) have no first-party EventData field list, so they use
lenient mode: each EventData field a rule uses maps to `EventData[Name]` and raises a `UserWarning`
that it isn't in a field list. Events that carry their payload in `UserData` (for example WMI-Activity 5857 to 5861, so a rule on `Consumer` or `PossibleCause`) convert under these profiles but never match. `windows_powershell_script` is strict (4103 to 4106 field names).
`windows_event_other` keyword search runs over `to_json(raw_event)` and is approximate. Classic
Windows PowerShell events 400, 600 and 800 (channel `Windows PowerShell`) have unnamed `Data`
elements; Sigma `Data` maps to all of them joined with newlines, so `Data|contains` and `Data|re`
work and any other field fails. `windows_event_logs` is the built-in header-only parser: rules that
need EventData fields fail with a hint to use the custom `windows_*` parsers. Sysmon `file_access`
and `file_rename` rules stay uncovered.

Measured on a Lakewatch workspace with synthetic data: 85 queries from 78 SigmaHQ Windows rule
files (Sysmon process, network, DNS and file events, 4688, 4624/4625/4720/4728, PowerShell script
blocks) all ran as valid SQL against the custom `windows_*` tables (3 of the sampled rules fail
closed). 14 hand-written rules built from values in the demo data each matched rows; the 7 other
positive queries target values the synthetic data doesn't hold, and returned 0 as expected. A
six-field Sysmon `process_creation` rule over 16M rows ran within 2x of a hand-written query that
casts `EventData` once in a subquery, so the profiles don't use a per-rule CTE. Converting the
whole SigmaHQ `rules/windows` tree with all 24 `windows_*` profiles yields queries for about 2,390
of 2,427 rule files (the rest fail closed, mostly on fields a profile can't express).

`crowdstrike_fdr_event` is written from the CrowdStrike Falcon Events Data Dictionary. It selects
events by `event_simpleName` and `event_platform` (`Win`, `Lin`, `Mac`), and reads the fields from
the `event` VARIANT. Live FDR data holds Windows paths both with drive letters and in the NT
device form, so a path with a drive letter matches either form (`C:\Windows\` also matches
`\Device\HarddiskVolume*\Windows\`). `file_event` includes `FileCreateInfo`, the event live
data uses for file creations. Its limitations:

* `Details` matches only string registry values (`RegStringValue`). Sysmon-style numeric and
  binary values (`DWORD (0x...)`, `QWORD (0x...)`, `Binary Data`) fail the rule.
* A `TargetObject` value ending with `\(Default)` fails the rule, and so does a hive after a
  leading wildcard (`*HKLM\SOFTWARE\...`).
* `Image`, and the other fields of the acting process, are available only in `process_creation`.
  FDR links the other events to their process by `ContextProcessId`, which needs a join.
* `network_connection` covers outbound connections only (`NetworkConnectIP4`/`IP6`), where FDR's
  local and remote addresses are Sigma's source and destination. Inbound connections aren't
  covered, and `Initiated: 'false'` fails the rule.
* Drive letters (`C:`) are rewritten only at the start of a value. A pattern with a drive letter
  later in the value, such as `Image|contains: 'C:\Users\'`, fails the rule.
* `ParentImage` matches the parent's base name (`ParentBaseFileName`), so a full parent path
  drops its directory with a warning. As live data can hold a full path there, the base name is
  matched exactly or as a `\name` suffix. `ParentCommandLine`, `ParentProcessId` (FDR's is a Falcon
  process id), `User`, `CurrentDirectory`, `Description`, `Product` and `Company` aren't
  supported.

`sentinelone_deep_visibility` is ported from the Apache-2.0 Panther pipeline (see
`THIRD_PARTY_NOTICES`). It selects events by `endpoint_os` and `event_type`, using only the event
types listed in SentinelOne's powerquery field reference (the header of the profile cites it).
Its limitations:

* `pipe_created`, `registry_add`, `registry_delete` and `registry_event` have no profile block
  and fail with the no-profile reason. Their event types (`Named Pipe Creation`, registry key
  events) aren't in the reference, so they wait for verification against real data.
  `registry_set` selects `Registry Value Modified`.
* `network_connection` and `firewall` select `IP Connect` with
  `event_network_direction = OUTGOING`, because S1's `src_*`/`dst_*` columns appear to be the
  process side and remote side, not the initiator and responder. `Initiated: 'false'` fails the
  rule, and `DestinationHostname` isn't supported (hostnames are on DNS events).
* `CurrentDirectory`, `Product`, `Protocol` and `record_type` aren't supported, and neither is
  `OriginalFileName` in `process_creation`.
* `Details` (`registry_value`) rejects Sysmon-style numeric and binary values (`DWORD (0x...)`,
  `QWORD (0x...)`, `Binary Data`). `TargetObject` is compared as written: the hive format of
  `registry_keyPath` is unverified.
* `file_event` selects `File Creation` only. The `endpoint_os` values (`windows`, `linux`,
  `osx`) come from Panther's pipeline and are unverified.

`carbonblack_endpoint_event` is ported from the Apache-2.0 Panther pipeline (see
`THIRD_PARTY_NOTICES`) and checked against the Carbon Black Cloud Data Forwarder `endpoint.event`
schema 1.2.0 (the header of the profile cites it). It selects events by `type`
(`endpoint.event.procstart`, `filemod`, `netconn`) and `device_os` (`WINDOWS`, `MAC`, `LINUX`).
Its limitations:

* In `process_creation`, `Image`, `CommandLine` and `User` are the new (child) process
  (`childproc_name`, `target_cmdline`, `childproc_username`), and `ParentImage`,
  `ParentCommandLine` and `ParentUser` are the actor process (`process_path`, `process_cmdline`,
  `process_username`). Panther's pipeline crossed these. `OriginalFileName`, `IntegrityLevel` and
  `CurrentDirectory` aren't supported.
* `network_connection` covers outbound connections only (`netconn_inbound = false`), because the
  schema's `local_*`/`remote_*` fields equal Sigma's source and destination only for outbound
  connections. `Initiated: 'false'` fails the rule. `Protocol` accepts `tcp` and `udp`
  (`PROTO_TCP`, `PROTO_UDP`, as listed for `netconn_protocol` in the Carbon Black Cloud Platform
  Search Fields reference); other values fail the rule.
* `file_event` selects every `endpoint.event.filemod` record: creations, deletions,
  modifications and renames. That is broader than Sysmon FileCreate.
* Only `process_creation`, `file_event` and `network_connection` have blocks. Other categories
  (`image_load`, `registry_set`, `dns_query`, ...) fail with the no-profile reason.

#### Keyword search and routing

**Keywords.** A keyword (a detection list without a field name) is searched in the raw event of
the profile. The profile says where it is with `raw:`, one of:

* `raw: {column: raw_line}`: a STRING column, searched as is (`contains(lower(col), lower('x'))`).
* `raw: {entries: EventData}`: the `_VALUE`s of the named entries joined with newlines.
* `raw: {expr: "to_json(raw_event)", encoding: json}`: any SQL expression; `encoding` is `text`
  or `json` and is required.

`-O raw_log_field=<column>` overrides the raw source of every selected profile with that column
(it must be a STRING column of each selected parser). A profile with no `raw` and no override
fails a rule with keywords: `no raw event for keyword search in profile <id>`.

Escaping caveats. Searches over `entries` and over `json` text are approximate and raise a
`UserWarning` (once per rule and profile):

* With `encoding: json`, keywords are JSON-escaped (`\` becomes `\\`, `"` becomes `\"`), then
  SQL-escaped, so a Windows path keyword matches the JSON text. Non-ASCII text is kept as is,
  but the JSON of a VARIANT may write it as `\uXXXX`. A regex keyword is not JSON-escaped (it
  warns), and a keyword that looks like a JSON fragment (`":` or `{`) warns too.
* With `entries`, a keyword can match across the join of two values, and it never sees the names.

**Routing.** A profile block can have `route: {field: EventID, in: [...]}` (or `not_in`). Parsers
split by EventID (Security, Sysmon, PowerShell) all match a service-based rule, so the rule is
converted only for the blocks whose route accepts at least one of the values the rule gives for
the field (wildcards always count, and so do values under `not`). A bare `route: {field: ...}`
uses the `allowed` list of the mapped schema field. A rule that never names the field goes to
every matching profile. If the rule matches the logsource of some profile but none routes, it
fails with `no selected Lakewatch parser profile accepts <field> values [...] of this rule`.

**Unmapped fields.** `event_data: any` accepts any EventData name (each use raises a
`UserWarning`); a list of names is strict. `unmapped_hint:` text is appended to the error of a
field the profile does not map.

## Deploying rules

To deploy the converted workspace rules, use one of the options below. Content-pack output isn't
deployed this way; install the pack instead.

**UI.** Open Detection rules, pick the rule, then Edit rule, Edit as YAML, and Save changes. See
[Edit a rule as YAML](https://docs.databricks.com/aws/en/lakewatch/detections/manage-detection-rules#edit-a-rule-as-yaml).
`catalog_name`, `schema_name` and `rule_name` can't be changed after the rule is created.

**One rule with the Databricks CLI** (Beta, CLI v1.27 or later). The CLI takes JSON, so convert the
YAML file first:

```bash
python -c 'import json,sys,yaml; json.dump(yaml.safe_load(open(sys.argv[1])), sys.stdout)' rule.yaml > rule.json
databricks lakewatch create-rule --json @rule.json --profile <profile>
```

**Many rules with `lakewatch-rule-deploy`.** The command creates or updates the workspace rules
written by `sigma convert -t databricks -f lakewatch`. It deploys detection rules only, not parsers,
data sources or content packs. Install it with the `deploy` extra:

```bash
pip install "pySigma-backend-databricks[deploy]"
```

```bash
sigma convert -s -t databricks -f lakewatch -O parsers=aws_cloudtrail \
  -O table_name=main.sec.aws_cloudtrail -O catalog_name=main -O schema_name=sec \
  -O warehouse_id=1234567890abcdef -O output_dir=detections rules/
lakewatch-rule-deploy --profile <profile> --dry-run detections/
lakewatch-rule-deploy --profile <profile> detections/
```

`PATH` is a rule file, a multi-document YAML file, or a directory. A directory is read for its
`*.yaml` files, not recursively; `conversion_report.yaml`, `revisions.yaml` and
`appIndex.rules.yaml` are skipped.

| Flag | Meaning |
|------|---------|
| `--profile PROFILE` | Databricks CLI profile. Default: the SDK's standard auth chain. A bad profile or missing credentials exit with 2; a rejected or expired token (401/403) fails on the first call and is reported as API errors (exit 4). |
| `--dry-run` | Validate and print the planned changes with their bodies; write nothing. |
| `--validate-only` | Validate the rules that would be created, updated or overwritten; write nothing. Unchanged and conflicting rules aren't validated. |
| `--force` | Overwrite rules that were not made from this Sigma rule. |
| `--warehouse-id ID` | Warehouse for the validateRule SQL dry run. Without it, the rule's `batch.warehouse_id` is used; with neither, validation is static only. |
| `--catalog C` | Replace `catalog_name` in every rule. `batch.sql.default_catalog_name` follows if it equals the original catalog. |
| `--schema S` | Replace `schema_name` in every rule. `batch.sql.default_schema_name` follows if it equals the original schema. |
| `--json` | Print the result as JSON. |

`--dry-run` and `--validate-only` are mutually exclusive.

How it works:

* Rules are identified by `(catalog_name, schema_name, rule_name)`. A rule is owned by the
  converter when the server's `annotations.sigma_id` equals the file's. An owned rule is created if
  missing, updated if it differs and left alone (`unchanged`) otherwise. Only changed top-level
  fields are sent.
* A rule that exists but isn't owned is a conflict and is left untouched. `--force` overwrites it.
  A rule without `annotations.sigma_id` is never owned, so redeploying it is always a conflict
  unless you pass `--force`.
* `schedule.enabled` is kept on update. A rule you enabled in the UI stays enabled, and redeploying
  never enables or disables a rule.
* Nothing is ever deleted.
* Every rule is checked with the server's validateRule before it's written. Pass `--warehouse-id`
  to include the SQL dry run. Rules with errors are reported as `invalid` and skipped.
* Creating or updating a rule starts a one-time run of it on the server. The output ends with a note
  when anything was written.
* Content-pack documents are rejected: `content-pack documents can't be deployed with
  lakewatch-rule-deploy; install the pack instead`.

Output is one line per rule, `<status> <catalog>.<schema>.<rule_name>`, with detail lines under it,
then a summary:

```
updated main.sec.encoded_powershell
  update_mask: batch,description
unchanged main.sec.suspicious_login
conflict main.sec.legacy_rule
  exists and was not made from this Sigma rule (server sigma_id: none, file sigma_id: 3f1c...)
created 0, updated 1, overwritten 0, unchanged 1, conflicts 1, invalid 0, errors 0
note: creating or updating a rule starts a one-time run of it on the server
```

Statuses are `created`, `updated`, `overwritten`, `planned` (valid, but nothing was written),
`unchanged`, `conflict`, `invalid` and `error`. Under `--dry-run` or `--validate-only` the summary
starts with `dry run: would ` or `validate only: would `, for example `would create 1`. With
`--json`, the output is `{"rules": [{"rule", "action", "status", "details"}], "summary": {...}}`;
`--dry-run` adds the planned `body` to each rule.

| Exit code | Meaning |
|-----------|---------|
| 0 | Everything is ok. |
| 2 | Local error: bad file, content-pack document, missing identity keys, duplicate rule, missing `deploy` extra, a bad profile, or no credentials. Nothing is written. |
| 3 | A conflict (without `--force`) or an invalid rule. |
| 4 | An API error, including a rejected or expired token (401/403). |

The highest applicable code wins.

## OCSF (optional)

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
* The options of [Lakewatch Output](#lakewatch-output) apply. The parsed-table options (`parsers`,
  `table_map`, `lakewatch_profiles_dir`, `lakewatch_schemas`) don't: `-O parsers` together with
  OCSF mode is a configuration error.
* Target modes, profile entities and summary overrides need parsed tables: `-O target=content_pack`
  fails in OCSF mode, `-O overrides` is ignored with a warning, and the summary is the rule title.
* With `-O output_dir`, one file per rule and `conversion_report.yaml` are written as in parsed
  mode (`profile` is `null` in the report).

### OCSF field rendering

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
enabled for rules processed by the OCSF pipeline (`-p ocsf`). For `lakewatch` without OCSF,
[parsed tables](#lakewatch-parsed-tables) are used.

## Maintainer

This backend is currently maintained by:

* [Alex Ott](https://github.com/alexott/)
