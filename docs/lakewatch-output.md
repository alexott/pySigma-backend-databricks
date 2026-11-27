# Lakewatch rule output

This page describes the rule documents that `-f lakewatch` writes: how Sigma metadata maps to them,
the output files, the `workspace` and `content_pack` target modes, and alert summaries. The
conversion options are listed in the [README](../README.md#lakewatch-options).

## Rule metadata

Only batch rules are generated (streaming is future work). Sigma metadata maps to Lakewatch as
follows:

* `title`→`output.summary`, `description`→`description`/`objective`, `level`→`severity`, and `attack.*` tags→`mitre`.
* The SQL filters on `IN_TIMERANGE(time)`, which follows the schedule.
* In parsed-table mode, each selected parser produces one rule per Sigma rule, named
  `<rule_name>__<profile>`, with `sigma_profile: <id>@<version>` in its annotations.
* `rule_name` is derived from the title in snake_case (e.g. `Encoded PowerShell` →
  `encoded_powershell`). Duplicate names within one output get `_2`, `_3`, … suffixes.
* Up to three Sigma `references` (each up to 512 characters) are emitted as `references`.
* A query over 65,536 bytes (the server's limit) fails the rule with `query is N bytes, ...`.
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
* `sigma_pruned_fields` is the last annotation, after `converter_version`. It lists the unsupported
  fields that were dropped from the rule, comma-separated, for example `"OriginalFileName"`, and it's
  only present when a field was dropped. Both targets have it. It depends only on the rule, so
  content hashes stay stable between runs. See
  [Pruning unsupported fields](writing-profiles.md#pruning-unsupported-fields).

## Output files

By default all rules go into one multi-document YAML file (`-o file.yaml`, or stdout). With
`-O output_dir=<dir>` each rule is written to its own `<dir>/<rule_name>.yaml`, and only a
one-line summary is printed. Files with the same name are overwritten, and other files in the
directory are left as they are. `output_dir` works only with the `lakewatch` format. Don't use the
`--output-dir`/`-od` option of sigma-cli with Lakewatch formats: it writes only the bare SQL condition
of each rule, not the rule documents.

## Target modes

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

## Alert summaries

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

## Content-pack output

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
