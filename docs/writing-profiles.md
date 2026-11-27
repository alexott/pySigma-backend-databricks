# Writing Lakewatch parser profiles

This document is for people who write or extend profiles. For the profiles that ship with the
backend and their known limitations, see [Built-in profiles](built-in-profiles.md).

## Profile format

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
default alert summary groups alerts by it (see [Alert summaries](lakewatch-output.md#alert-summaries)). All built-in
profiles have an `entity`.

VARIANT paths render as `try_variant_get(col, '$.path', 'type')`, and paths through arrays as
`exists(col, x0 -> ...)`.

An array inside a VARIANT column matches the same way, but only when the parser schema declares the
array. The target is then the leaf path without a `[]` marker, and a rule matches when any element
matches. It renders as
`exists(try_variant_get(col, '$.path', 'ARRAY<VARIANT>'), x0 -> ...)`, or with `'ARRAY<<elem>>'`
when the elements are scalars. Each condition gets its own `exists()`, so two conditions on the same array may match
different elements. An array the schema doesn't declare gets no such rendering.

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
  declared array one level inside a VARIANT. `[*]` isn't supported on a declared column and fails with an error that mentions `entries`. A
  declared VARIANT array has no single-object fallback, unlike an undeclared VARIANT column.
* A column without an `entries` key uses `_Name` and `_VALUE`. A target with `[Name]` also works
  for `entity`.

## Strict field mapping

Field mapping is strict. A Sigma field that isn't a key of the profile's `fields` fails that
rule with `field <name> is not mapped by profile <id>`, unless the profile accepts it through
`event_data` or a prefix mapping. Keyword (unbound) searches fail unless the profile sets `raw` (see
[Keyword search and routing](#keyword-search-and-routing)). Use `-s` to skip failed rules when
converting a directory.

## Value transforms

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
  (`contains`, `startswith`, `endswith`, `re`, `cidr`, `gt`, `gte`, `lt`, `lte`, `neq`, `exists`, `fieldref`)
  is present, the comparison is an equality, so the field must allow `eq` as well. For example,
  `c-uri|all: [...]` needs both `eq` and `all` in the list, and fails otherwise, while
  `c-uri|contains|all` needs only `contains` and `all`.
* `undeclared: true` allows a target inside a VARIANT column that declares sub-fields, but not
  this one: a key that the data has and the parser schema doesn't list. It is extracted as a
  string.
* The top-level `products` map adds conditions per Sigma product, for example
  `products: {windows: {event_platform: Win}}`. Block conditions win on the same field. With
  `products` set, a rule whose product isn't listed doesn't match the profile.

Comparisons against a whole VARIANT column are limited: `|contains` is matched approximately
against the JSON text, with a warning, and other comparisons fail the rule. Use a path such as
`requestParameters.bucketName` for exact matching. With `sigma convert -s`, failed rules are
skipped and reported.


## Keyword search and routing

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

## Scaffolding a profile

Writing profiles: `scripts/scaffold_profile.py PARSER --match product=windows,category=process_creation --rules <sigma rules dir>`
writes a starting profile with one identity line per schema path, a `# used by N rules` comment
on each path that matching rules use, and a trailing list of Sigma fields the schema lacks. Use
`--schemas` for a schema file that isn't built in. To build such a file from a table, run
`scripts/describe_to_schema.py --parser NAME -o out.json` with either `--describe-json FILE` (the
output of `DESCRIBE TABLE EXTENDED <table> AS JSON`) or `--table c.s.t --profile P --warehouse-id W`,
which runs the statement through the `databricks` CLI. `--profile` is never defaulted.

## Validation against live data

Check a new profile against real tables before you rely on it: run the converted queries, and
compare matches and run time with a hand-written query. For example, this is how the Windows
profiles were checked:

Measured on a Lakewatch workspace with synthetic data: 85 queries from 78 SigmaHQ Windows rule
files (Sysmon process, network, DNS and file events, 4688, 4624/4625/4720/4728, PowerShell script
blocks) all ran as valid SQL against the custom `windows_*` tables (3 of the sampled rules fail
closed). 14 hand-written rules built from values in the demo data each matched rows; the 7 other
positive queries target values the synthetic data doesn't hold, and returned 0 as expected. A
six-field Sysmon `process_creation` rule over 16M rows ran within 2x of a hand-written query that
casts `EventData` once in a subquery, so the profiles don't use a per-rule CTE. Converting the
whole SigmaHQ `rules/windows` tree with all 24 `windows_*` profiles yields queries for about 2,390
of 2,427 rule files (the rest fail closed, mostly on fields a profile can't express).
