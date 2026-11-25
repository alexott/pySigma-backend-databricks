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
* lakewatch: Lakewatch detection rules in the v1 format (`kind: Rule` YAML), batch by default
* lakewatch_v2: Lakewatch detection rules in the v2 (Beta) format, batch by default

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

### Lakewatch v2 format

The `lakewatch` format generates rules in the v1 format. Use `-f lakewatch_v2` for the v2 (Beta)
format, where each rule is a Unity Catalog governed resource:

```bash
sigma convert -t databricks -f lakewatch_v2 -p ocsf \
  -O catalog_name=main -O schema_name=security -O warehouse_id=1234567890abcdef rules/ -o detections.yaml
```

The `table_name`, `schedule`, `default_fidelity` and `default_category` options work as for v1.
`compute_group` is ignored, with a warning, because the v2 API removed `schedule.compute_group`.
The v2 format has these additional options:

| Option | Default | Meaning |
|--------|---------|---------|
| `catalog_name` | *(required)* | `catalog_name` of the rule, also used as `batch.sql.default_catalog_name` to resolve unqualified tables. Conversion fails if unset or empty. |
| `schema_name` | *(required)* | `schema_name` of the rule, also used as `batch.sql.default_schema_name`. Conversion fails if unset or empty. |
| `warehouse_id` | *(none)* | `batch.warehouse_id`: SQL warehouse that runs the rule. The server rejects enabled batch rules without one, so conversion warns if it's unset. |
| `extend_lookback` | *(none)* | `timerange.extend_lookback`: widens the time window beyond the schedule. |
| `enabled` | `false` | `schedule.enabled`. Converted rules are disabled by default so that they can be reviewed and tested first; set `-O enabled=true` to schedule them immediately. |

Differences from v1:

* The SQL filters on `IN_TIMERANGE(time)`, which follows the schedule, instead of a fixed
  `lookback` interval (the `lookback` option is ignored).
* `rule_name` is derived from the title in snake_case (e.g. `Encoded PowerShell` →
  `encoded_powershell`). Duplicate names within one output get `_2`, `_3`, … suffixes.
* Up to three Sigma `references` (each up to 512 characters) are emitted as `references`.
* Fidelity values use the v2 enum names. Converted rules haven't been tested against your data, so
  Sigma `stable` maps to `FIDELITY_INVESTIGATIVE` and every other status to `FIDELITY_DEVELOPMENT`.
  `default_fidelity` overrides this and accepts both `Investigative` and `FIDELITY_INVESTIGATIVE`.
* Rules are emitted with `schedule.enabled: false` (see the `enabled` option), and without
  `schedule.compute_group`.
* `output.event_time_column` is `time`.
* `description` is cut to 4096 characters and `objective` to 65536. Cut values end with `...`.
* Sigma `falsepositives` become the `runbook` ("Known false positives: …", up to 4096 characters).
* `annotations` record where the rule came from: `sigma_id`, `sigma_status`, `sigma_author`,
  `sigma_tags` (tags other than ATT&CK) and `converter_version`. Values are cut to 256 characters,
  and empty values are left out.

### Lakewatch v2 parsed tables

**Breaking change in the next release (0.2.0).** For `lakewatch_v2`, parsed-table mode is now the
default. Rules are converted against the columns of a Lakewatch parser's table instead of OCSF
gold tables. `-f lakewatch_v2` without `-p ocsf` therefore needs `-O parsers=...`. To keep the
previous OCSF behavior, pass `-O ocsf=true` (or `-p ocsf`, which still selects OCSF).

```bash
sigma convert -s -t databricks -f lakewatch_v2 -O parsers=aws_cloudtrail \
  -O table_name=main.sec.aws_cloudtrail -O catalog_name=main -O schema_name=sec \
  -O warehouse_id=1234567890abcdef rules/ -o detections.yaml
```

Each selected parser produces one rule per Sigma rule, named `<rule_name>__<profile>`, with
`sigma_profile: <id>@<version>` in its annotations. Options:

| Option | Default | Meaning |
|--------|---------|---------|
| `parsers` | *(required)* | Comma-separated profile ids, for example `aws_cloudtrail,okta_system_log`. |
| `table_name` | *(none)* | Table to read from. Use it when exactly one parser is selected. |
| `table_map` | *(none)* | `profile:table,profile:table` for several parsers. Every selected profile needs a table. |
| `lakewatch_profiles_dir` | *(none)* | Directory with your own `*.yml` profiles. They are added to the built-in ones, and an id replaces a built-in id. |
| `lakewatch_schemas` | *(none)* | JSON file with additional parser schemas, in the format of the bundled catalog. |
| `output_dir` | *(none)* | Write one `<rule_name>.yaml` file per rule into this directory (created if missing) instead of one multi-document YAML file. |

By default all rules go into one multi-document YAML file (`-o file.yaml`, or stdout). With
`-O output_dir=<dir>` each rule is written to its own `<dir>/<rule_name>.yaml`, and only a
one-line summary is printed. Files with the same name are overwritten, and other files in the
directory are left as they are. `output_dir` works only with `lakewatch_v2`. Don't use the
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
logsources:
  - match: {product: aws, service: cloudtrail}   # product, category and service
    conditions:
      eventType: AwsApiCall                 # added to every rule with this logsource
    unsupported: [Destination]              # fail with a clear message
```

VARIANT paths render as `try_variant_get(col, '$.path', 'type')`, and paths through arrays as
`exists(col, x0 -> ...)`.

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
| `basename` | none | `C:\dir\cmd.exe` and `*\cmd.exe` become `cmd.exe`. Fails for patterns on the directory, such as `startswith`. |
| `path_prefix` | `rewrite: [{from: <regex>, to: <prefix>}]` | Rewrites the start of a path, for example `C:` to `\Device\HarddiskVolume*`. Fails when a `from` match follows a leading wildcard (`*C:\...`). |
| `registry_path` | `hive: short \| long \| kernel`, optional `split: {key: <path>, value: <path>}` | Normalizes the hive name (`HKLM`, `HKEY_LOCAL_MACHINE`, `\REGISTRY\MACHINE`, ...). With `split`, see below. |
| `hashes` | `algos: {MD5: <path>, SHA1: <path>, SHA256: <path>, IMPHASH: <path>}` | Routes `ALGO=digest` values (or a bare digest, by its length) to the column of the algorithm. |
| `domain_user` | `{domain: <path>, user: <path>}` | Matches `DOMAIN\user` values, see below. |
| `regex_replace` | `pattern`, `replacement` | Regex substitution on the literal parts of a string. |
| `to_int`, `to_str` | none | Converts digit strings to numbers, or numbers and booleans to strings. |

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
* `select_condition` maps each value (case-insensitive; `true`/`false` for booleans) to
  conditions that are ANDed. Several values are ORed, and `not` works as usual. Another value,
  or a wildcard, fails the rule. When the rule doesn't use the field, only the block conditions
  apply.
* `modifiers` lists the Sigma modifiers allowed on a field (`eq` for none). Any other modifier
  fails the rule with `field <F>: modifier <m> is not supported`.
* `undeclared: true` allows a target inside a VARIANT column that declares sub-fields, but not
  this one: a key that the data has and the parser schema doesn't list. It is extracted as a
  string.
* The top-level `products` map adds conditions per Sigma product, for example
  `products: {windows: {event_platform: Win}}`. Block conditions win on the same field. With
  `products` set, a rule whose product isn't listed doesn't match the profile.

Current limitations:

* Keyword (unbound) searches aren't supported yet.
* Comparisons against a whole VARIANT column aren't supported yet, for example
  `requestParameters|contains`. Use a path such as `requestParameters.bucketName` instead.
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
| `crowdstrike_fdr_event` | `product: windows`, `linux` or `macos` with `category: process_creation`; `product: windows` with `category: network_connection`, `dns_query`, `file_event` or `registry_set` | `crowdstrike_fdr_event` |
| `sentinelone_deep_visibility` | `product: windows`, `linux` or `macos` with `category: process_creation`, `file_event`, `file_change`, `file_rename`, `file_delete`, `image_load`, `registry_set`, `dns_query`, `dns`, `network_connection` or `firewall` | `sentinelone_deep_visibility` |
| `carbonblack_endpoint_event` | `product: windows`, `linux` or `macos` with `category: process_creation`, `file_event` or `network_connection` | `carbonblack_endpoint_event` |

`crowdstrike_fdr_event` is written from the CrowdStrike Falcon Events Data Dictionary. It selects
events by `event_simpleName` and `event_platform` (`Win`, `Lin`, `Mac`), and reads the fields from
the `event` VARIANT. Windows paths are rewritten to the NT device form
(`C:` becomes `\Device\HarddiskVolume*`). Its limitations:

* `Details` matches only string registry values (`RegStringValue`). Numeric and binary values
  aren't matched.
* `Image`, and the other fields of the acting process, are available only in `process_creation`.
  FDR links the other events to their process by `ContextProcessId`, which needs a join.
* `network_connection` covers outbound connections only (`NetworkConnectIP4`/`IP6`), where FDR's
  local and remote addresses are Sigma's source and destination. Inbound connections aren't
  covered, and `Initiated: 'false'` fails the rule.
* Drive letters (`C:`) are rewritten only at the start of a value. A pattern with a drive letter
  later in the value, such as `Image|contains: 'C:\Users\'`, fails the rule.
* `ParentImage` matches the parent's base name (`ParentBaseFileName`), so a full parent path
  drops its directory with a warning. `ParentCommandLine`, `ParentProcessId` (FDR's is a Falcon
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
  connections. `Initiated: 'false'` fails the rule. `Protocol` accepts `tcp` and `udp`; `PROTO_TCP`
  is inferred from the documented `PROTO_UDP`.
* Only `process_creation`, `file_event` and `network_connection` have blocks. Other categories
  (`image_load`, `registry_set`, `dns_query`, ...) fail with the no-profile reason.

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
enabled for the `lakewatch` format and for rules processed by the OCSF pipeline (`-p ocsf`). For
`lakewatch_v2` it is enabled only by `-O ocsf=true` or an OCSF pipeline; otherwise
[parsed tables](#lakewatch-v2-parsed-tables) are used.

## Maintainer

This backend is currently maintained by:

* [Alex Ott](https://github.com/alexott/)
