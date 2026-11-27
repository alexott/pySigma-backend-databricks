# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.0] - 2026-11-27

### Breaking changes

- **Parsed tables are the default for `-f lakewatch`.** Rules are converted against the columns
  of a Lakewatch parser's table instead of OCSF gold tables, so `-f lakewatch` without `-p ocsf`
  needs `-O parsers=...`. Without it, no rules are converted: parser discovery runs and reports
  which profiles can convert the rules. To keep the OCSF behavior, pass `-O ocsf=true`, or
  `-p ocsf`, which still selects OCSF.
- The Lakewatch v1 rule format (`kind: Rule` YAML) was removed.
- The `lakewatch_v2` format was renamed to `lakewatch`, with no alias: `-f lakewatch_v2` fails
  with the unknown-format error.
- The `compute_group` and `lookback` options were removed. Passing either is now a configuration
  error. To widen the time window, use `-O extend_lookback=...`.
- The failure message for unbound keywords changed.
- `warehouse_id` is required for workspace rules; conversion fails without it.
- `lakewatch-rule-deploy --warehouse-id` (and `deploy(warehouse_id=...)` in Python) replaces `batch.warehouse_id` in every rule (it was the
  validation warehouse only).
- `fieldref|startswith`, `fieldref|endswith` and `fieldref|contains` now convert in every output
  format.
- The SQL for named entries (`Field[Name]`) has a fallback for single-object values.

### Added

- A Lakewatch rule whose SQL is over the server's 65,536-byte limit fails at conversion
  (`query is N bytes, ...`) and shows up in the conversion report.
- Equality lists on one field render as `IN (...)`, and `|cidr` lists as one
  `exists(array(...), ...)`, so a long list repeats the field expression once. Number lists merge
  into `IN` only for Lakewatch parsed tables (typed columns).
- **Implied `eq` in the `modifiers` allowlist:** a field with no comparison modifier
  (`contains`, `startswith`, `endswith`, `re`, `cidr`, `gt`, `gte`, `lt`, `lte`, `neq`, `exists`, `fieldref`)
  is now checked as `eq`, so `field|all` alone fails unless the profile lists `eq`.
- **`join` transform:** matches two scalar columns joined with a non-empty `sep`, rendered as
  `concat_ws(sep, nullif(a, ''), nullif(b, ''))`. `null` on a joined field fails to convert.
- **Arrays inside a VARIANT:** a declared array inside a VARIANT column matches any element, rendered as
  `exists(try_variant_get(col, '$.path', 'ARRAY<VARIANT>' or 'ARRAY<<elem>>'), x0 -> ...)`. Arrays the
  schema doesn't declare get no such rendering.
- **`entries` profile key:** named entries with configurable `name` and `value` members (`value` may be a
  list, coalesced as strings) and `ignore_case`. It works on a top-level VARIANT, a top-level
  `ARRAY<STRUCT>` and a one-level declared VARIANT array, and for `entity`. `[*]` isn't supported on a
  declared column and fails with an error that mentions `entries`.
- **Azure Lakewatch profiles:** built-in `azure_audit`, `azure_signin`, `azure_monitor_activity`
  and `azure_identity_protection` profiles for the `product: azure` services `auditlogs`,
  `signinlogs`, `activitylogs` and `riskdetection`. The SigmaHQ `cloud/azure` rules go from 0/123
  to 102/123 convertible. PIM rules have no Lakewatch parser, sign-in `Status`,
  `ActivityDetails` and `properties.message` aren't supported, and array fields support only `|contains`, matched
  approximately against the JSON text.
- **Microsoft 365 Lakewatch profiles:** built-in `microsoft365_audit_general`,
  `microsoft365_audit_azure_active_directory` and `microsoft365_audit_exchange` profiles for the
  `product: m365` services `audit` and `exchange`. The SigmaHQ `cloud/m365` rules
  go from 0/19 to 5/19 convertible. `threat_management` and `threat_detection` alert rules aren't
  supported yet, `OperationProperties` isn't mapped, and in the Exchange profile only `status: success` is mapped.
- **GCP and Google Workspace Lakewatch profiles:** built-in `gcp_audit_log` and
  `google_workspace_reports` profiles for `product: gcp` (`service: gcp.audit`, `google_workspace.admin` and `google_workspace.login`). The SigmaHQ `cloud/gcp` rules go from 0/26 to 25/26 convertible.
  Keyword searches aren't supported, and in `google_workspace_reports` only the `admin` and `login` service values are mapped.
- **Web Lakewatch profiles:** built-in `cloudflare_http_request`, `gcp_http_load_balancer`, `akamai_waf` and
  `aws_waf_web_acl` profiles for `category: webserver`, and `zscaler_zia_web_log` and `ciscoumbrella_proxy`
  profiles for `category: proxy`. The SigmaHQ `webserver` and `proxy` rules convert on 51 to 72 of 86 and 47 of 56
  rules per profile. Keyword searches fail except on Zscaler (approximate, over `to_json(event)`), unmapped fields fail, and the GCP, Zscaler and Umbrella whole-URL fields allow only
  the modifiers `contains`, `endswith`, `re` and `all` (`all` in combination with them).
- `lakewatch-rule-deploy` command (installed with the `deploy` extra: `pip install
  "pySigma-backend-databricks[deploy]"`). It creates or updates the workspace rules written by
  `-f lakewatch` in a Databricks workspace, with `--dry-run`, `--validate-only` and `--force`.
- Lakewatch parsed-table mode: mapping profiles that convert Sigma rules to the output tables of
  Lakewatch parsers, selected with `-O parsers=...`. Related options:
  - `-O table_name` and `-O table_map` set the tables to read from;
  - `-O lakewatch_profiles_dir` adds user profiles;
  - `-O lakewatch_schemas` adds parser schemas.
- Built-in profiles:
  - AWS CloudTrail;
  - Okta System Log;
  - CrowdStrike FDR;
  - SentinelOne Deep Visibility;
  - Carbon Black endpoint events;
  - Windows Event Log: Sysmon, Security, PowerShell, the channel parsers, a catch-all, and the
    header-only `windows_event_logs`.
- Conversion report: with `-O output_dir`, `conversion_report.yaml` is written into the output
  directory, in workspace and content-pack mode. It lists the status of each rule (converted,
  failed or skipped) with the reason, the profile results with the rule names, how each field was
  resolved, the captured warnings, an `approximate` flag and lint hints, and totals by logsource.
  In Python, `backend.last_report` has the same structure.
- Parser discovery: without `-O parsers`, `-f lakewatch` reports which profiles can convert each
  rule and suggests a `-O parsers=...` value. `DatabricksBackend.discover_parsers()` does the same
  in Python.
- Schema-aware field rendering: STRUCT access, `try_variant_get()` for VARIANT keys, `exists()`
  over arrays, and named entries such as `EventData[Name]`.
- Profile value transforms (base name, hashes, registry paths, `to_hex`, `first_set` and others),
  field selection by condition, and routing by EventID.
- Keyword search over a profile's raw event source.
- The `-O output_dir` option, which writes one `<rule_name>.yaml` per rule.
- `-O target=content_pack|workspace` for `-f lakewatch` (default `workspace`). `content_pack`
  creates Lakewatch content-pack rule documents, with a deterministic UUIDv4
  `content_resource_id` per rule and a parser uuid from the schema catalog. Content-pack
  documents have no `converter_version` annotation, so converter releases don't bump every
  rule's version. With `-O output_dir` pointed at a pack's `rules/` directory
  it writes `<name>/<name>.yaml`, merges `revisions.yaml` (content hashes and versions, edited as
  text) and writes an `appIndex.rules.yaml` fragment.
- Profile `entity` key. Each query selects it as `sigma_entity`, and the default alert summary is
  `<title> on {sigma_entity}`. All built-in profiles define one.
- Summary overrides: the `lakewatch:` rule attribute and `-O overrides=<file>` set `summary`,
  `context` and `select` (extra output columns) per rule. The overrides file may be scoped by
  profile, and settings merge per key.
- The tools `scripts/scaffold_profile.py`, `scripts/describe_to_schema.py` and
  `scripts/gen_lakewatch_v2_schemas.py`.
- The Lakewatch v2 rule format (#129), aligned with the current v2 rule contract (#140):
  - Unity Catalog governed documents, with the `catalog_name` and `schema_name` options;
  - `IN_TIMERANGE(time)` filtering;
  - the `warehouse_id`, `extend_lookback` and `enabled` options;
  - `runbook` and provenance `annotations`.
- OCSF array and free-form fields are rendered with `exists()` and the JSON path syntax (#128).

### Changed

- ASCII string literals are lowercased by the converter (`lower(F) = 'v'` instead of `lower(F) = lower('V')`);
  non-ASCII literals keep `lower()`. Subclasses that override `contains_expression`,
  `startswith_expression` or `endswith_expression` now receive the already case-folded value (`{value}`
  is no longer wrapped in `lower()` by the templates).
- **Documentation:** the README now covers installation, a Lakewatch quick start, the main options
  and deployment. The details moved to `docs/`: `lakewatch-output.md`, `discovery-and-reports.md`,
  `built-in-profiles.md`, `writing-profiles.md`, `deploying.md` and `ocsf.md`.
- **Profiles use the new features:** `akamai_waf` and `aws_waf_web_acl` map `cs-uri-query` through `join`
  (path and query joined with `?`), converting 60 and 51 of the 86 SigmaHQ `webserver` rules. A rule with
  `cs-uri-query: null` (one corpus rule, CVE-2026-63030) fails to convert on these two profiles, because a
  joined field is never NULL. `aws_waf_web_acl` maps `cs-user-agent`, `cs-referer` and `cs-host` to the
  `httpRequest.headers` entries (`entries`, case-insensitive). `gcp_audit_log` matches the
  `authorizationInfo` array any-element, and `google_workspace_reports` maps `setting_name` and `new_value` to the
  `parameters` entries (`value` or `boolValue`).

### Fixed

- OCSF class uids of the application classes (#128).

## [0.1.7] - 2026-10-19

### Changed

- The `|cidr` modifier uses the built-in Databricks IP functions `ip_cidr_contains` and
  `try_ip_as_binary`, which need Databricks Runtime 18.2+ (#127).
- Updated pySigma to 1.5.1.

### Added

- Support for the `|exists` modifier (#120).

### Fixed

- SQL escaping of regular expressions and matching of wildcards (#120).

## [0.1.6] - 2026-10-08

### Added

- Experimental Lakewatch output format (v1 rules) with OCSF gold-table resolution (#109).
- Explicit registration of the processing pipelines.

### Changed

- Updated pySigma to 1.5.

### Fixed

- The release workflow.

## [0.1.5] - 2026-01-04

The first release published to PyPI.

### Added

- The `default`, `dbsql` and `detection_yaml` output formats, and the `snake_case` processing
  pipeline.
- Support for unbound keyword rules (#37).
- Field-to-field comparisons (`fieldref`) (#35).
- ORs of string matches on the same field are optimized into one regular expression (#36).

### Changed

- Support for pySigma 1.0 and sigma-cli 2.0.

### Fixed

- Rules without a `status` (#35).

[Unreleased]: https://github.com/alexott/pySigma-backend-databricks/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/alexott/pySigma-backend-databricks/compare/v0.1.7...v0.2.0
[0.1.7]: https://github.com/alexott/pySigma-backend-databricks/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/alexott/pySigma-backend-databricks/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/alexott/pySigma-backend-databricks/releases/tag/v0.1.5
