# Deploying rules with lakewatch-rule-deploy

`lakewatch-rule-deploy` creates or updates the workspace rules written by
`sigma convert -t databricks -f lakewatch`. The [README](../README.md#deploying-rules) shows how to
install and run it. This page describes its input, its flags, how it decides what to write, and its
output.

## Input

`PATH` is a rule file, a multi-document YAML file, or a directory. A directory is read for its
`*.yaml` files, not recursively; `conversion_report.yaml`, `revisions.yaml` and
`appIndex.rules.yaml` are skipped.

## Flags

| Flag | Meaning |
|------|---------|
| `--profile PROFILE` | Databricks CLI profile. Default: the SDK's standard auth chain. A bad profile or missing credentials exit with 2; a rejected or expired token (401/403) fails on the first call and is reported as API errors (exit 4). |
| `--dry-run` | Validate and print the planned changes with their bodies; write nothing. |
| `--validate-only` | Validate the rules that would be created, updated or overwritten; write nothing. Unchanged and conflicting rules aren't validated. |
| `--force` | Overwrite rules that were not made from this Sigma rule. |
| `--warehouse-id ID` | Deploy with another SQL warehouse than the one in the files: replaces `batch.warehouse_id` in every rule. Also used for the validateRule SQL dry run, which otherwise uses each rule's own warehouse. |
| `--catalog C` | Replace `catalog_name` in every rule. `batch.sql.default_catalog_name` follows if it equals the original catalog. |
| `--schema S` | Replace `schema_name` in every rule. `batch.sql.default_schema_name` follows if it equals the original schema. |
| `--json` | Print the result as JSON. |

`--dry-run` and `--validate-only` are mutually exclusive.

## How it works

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
* Every rule is checked with the server's validateRule before it's written. The SQL dry run runs on
  the rule's `batch.warehouse_id`. Rules with errors are reported as `invalid` and skipped.
* Creating or updating a rule starts a one-time run of it on the server. The output ends with a note
  when anything was written.
* Content-pack documents are rejected: `content-pack documents can't be deployed with
  lakewatch-rule-deploy; install the pack instead`.

## Output and exit codes

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
