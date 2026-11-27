# Parser discovery and conversion reports

## Parser discovery

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

## Conversion report

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
  -O catalog_name=main -O schema_name=sec -O warehouse_id=1234567890abcdef -O output_dir=out rules/windows/
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
    pruned: []
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
* **`pruned`**: the unsupported fields that were dropped from the rule, in rule order, or `[]`.
  Every result has the key. A pruned rule is narrower than written, and the result carries the
  `LakewatchPrunedWarning` text in `warnings`. It isn't `approximate`. See
  [Pruning unsupported fields](writing-profiles.md#pruning-unsupported-fields).
* **`lint`**: hints that don't fail the rule. For a `lenient` field whose name matches a top-level
  column of the parser, ignoring case: `field <F> is read from <col>[<F>] by event_data any, but <Column> is a top-level column of parser <parser>; map it explicitly`.

In Python, `backend.last_report` holds the report of the last `lakewatch` conversion, in the same
structure as the file (`None` before the first one, after a discovery run, and after a run that aborted with an error). `write_report` in
`sigma.backends.databricks.lakewatch_report` writes it.
