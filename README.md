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
| `basename` | none, or optional `also_suffix: true \| false` (`false`) | Keeps the last path component: `C:\dir\cmd.exe` and `*\cmd.exe` become `cmd.exe`, and `*cmd.exe` is kept. Fails for patterns on the directory, such as `startswith`, or `contains` without a separator (`*Microsoft Office*`). With `also_suffix: true`, the column can hold a base name or a full path. Each base name `N` matches `N` exactly or ends with `\N`. Values without a separator count as base names too, including ones with an inner wildcard (`cmd.exe`, `py*.exe`, `?md.exe`). A value that used `/` (`/usr/bin/bash`) also matches a value ending with `/N`. A value starting with `*` and no separator (`*cmd.exe`) already matches both forms, so it stays as is. |
| `path_prefix` | `rewrite: [{from: <regex>, to: <prefix>}]`, optional `keep_original: true \| false` (`false`) | Rewrites the start of a path, for example `C:` to `\Device\HarddiskVolume*`. With `keep_original`, a rewritten value matches the original or the rewritten form. Fails when a `from` match follows a leading wildcard (`*C:\...`). |
| `registry_path` | `hive: short \| long \| kernel`, optional `split: {key: <path>, value: <path>}` | Normalizes the hive name (`HKLM`, `HKEY_LOCAL_MACHINE`, `\REGISTRY\MACHINE`, ...) at the start of a value. Fails when a hive follows a leading wildcard (`*HKLM\SOFTWARE\...`). With `split`, see below. |
| `hashes` | `algos: {MD5: <path>, SHA1: <path>, SHA256: <path>, IMPHASH: <path>}` | Routes `ALGO=digest` values (or a bare digest, by its length) to the column of the algorithm. |
| `domain_user` | `{domain: <path>, user: <path>}` | Matches `DOMAIN\user` values, see below. |
| `regex_replace` | `pattern`, `replacement` | Regex substitution on the literal parts of a string. |
| `to_hex` | none, or optional `prefix: <str>` (`0x`) | Turns an exact decimal number into lowercase hex with the prefix (`4120` becomes `0x1018`). Fails for wildcards, negative numbers, ordering comparisons and regular expressions. |
| `first_set` | `candidates: [<path> \| {domain: <path>, user: <path>}, ...]` (at least 2), optional `unset: [<str>]` (`['-']`) | Matches the first candidate that is set (not NULL, empty or in `unset`), rendered as a `CASE WHEN` expression; the condition applies to it unchanged. A `{domain, user}` candidate is the joined `DOMAIN\user`. Must be the last transform; field references to it fail. |
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
that it isn't in a field list. `windows_powershell_script` is strict (4103 to 4106 field names).
`windows_event_other` keyword search runs over `to_json(raw_event)` and is approximate. Classic
Windows PowerShell events 400, 600 and 800 (channel `Windows PowerShell`) have unnamed `Data`
elements; Sigma `Data` maps to all of them joined with newlines, so `Data|contains` and `Data|re`
work and any other field fails. `windows_event_logs` is the built-in header-only parser: rules that
need EventData fields fail with a hint to use the custom `windows_*` parsers. Sysmon `file_access`
and `file_rename` rules stay uncovered.

Measured on a Lakewatch workspace: 85 SigmaHQ Windows rules (Sysmon process, network, DNS and file
events, 4688, 4624/4625/4720/4728, PowerShell script blocks) all ran as valid SQL against the
custom `windows_*` tables, and 14 hand-written rules built from the demo data all matched rows
(synthetic data). A six-field Sysmon `process_creation` rule over 16M rows ran in about 4 s as
converted and about 3 s with `EventData` cast once in a subquery. Converting the whole SigmaHQ
`rules/windows` tree with all 24 `windows_*` profiles yields queries for about 2,390 of 2,427 rule files
(the rest fail closed, mostly on fields a profile can't express).

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
