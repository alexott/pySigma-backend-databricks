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

* `lakewatch`: Lakewatch detection rules (Unity Catalog governed), batch by default;
* `default`: plain Databricks/Apache Spark SQL queries;
* `dbsql`: Databricks SQL queries with rules metadata (title, status) embedded as comment;
* `detection_yaml`: Yaml markup for my own detection framework.

## Installation

```bash
pip install sigma-cli pySigma-backend-databricks
```

To deploy Lakewatch rules with `lakewatch-rule-deploy`, install the `deploy` extra as well (see
[Deploying rules](#deploying-rules)).

## Documentation

The README covers what you need to get started. The details are in `docs/`:

| Document | Contents |
|----------|----------|
| [Lakewatch rule output](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/lakewatch-output.md) | Sigma metadata mapping, output files, target modes (`workspace`, `content_pack`), content-pack output, alert summaries and overrides |
| [Parser discovery and conversion reports](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/discovery-and-reports.md) | Finding the parsers that fit your rules, and the `conversion_report.yaml` format |
| [Built-in profiles](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/built-in-profiles.md) | The profile of each supported parser, and its known limitations |
| [Writing profiles](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/writing-profiles.md) | Profile format, VARIANT paths and named entries, value transforms, keyword search and routing, scaffolding scripts, validation against live data |
| [Deploying rules](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/deploying.md) | `lakewatch-rule-deploy` in detail: ownership, updates, output and exit codes |
| [OCSF mode](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/ocsf.md) | Converting against OCSF gold tables, and how OCSF fields are rendered |

## Lakewatch Output

Generate [Lakewatch](https://www.databricks.com/product/lakewatch) detection rules from Sigma rules
(see the [Lakewatch documentation](https://docs.databricks.com/aws/en/lakewatch/)). Each rule is a
Unity Catalog governed resource. Rules are converted against the tables of Lakewatch parsers. A
*profile* maps the Sigma fields of a logsource to the columns of one parser's table, and the backend
ships a profile for each supported parser (see
[Built-in profiles](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/built-in-profiles.md)).
Converting against OCSF gold tables is optional (see
[OCSF mode](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/ocsf.md)).

### Lakewatch quick start

1. **Find the parsers that fit your rules.** Without `-O parsers`, nothing is converted. Instead,
   the backend reports which profiles can convert each rule, and suggests a `-O parsers=...` value:

   ```bash
   sigma convert -t databricks -f lakewatch rules/windows/
   ```

   Pick the parsers whose data you ingest: the suggestion lists every profile that fits. See
   [Parser discovery](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/discovery-and-reports.md#parser-discovery).

2. **Convert the rules** for the selected parsers. `-s` skips the rules that fail, instead of
   stopping at the first error:

   ```bash
   sigma convert -s -t databricks -f lakewatch -O parsers=aws_cloudtrail \
     -O table_name=main.sec.aws_cloudtrail -O catalog_name=main -O schema_name=sec \
     -O warehouse_id=1234567890abcdef rules/ -o detections.yaml
   ```

   With several parsers, give each its table with `table_map`:

   ```bash
   sigma convert -s -t databricks -f lakewatch \
     -O parsers=windows_sysmon_process,windows_security_process \
     -O table_map=windows_sysmon_process:main.sec.sysmon,windows_security_process:main.sec.winsec \
     -O catalog_name=main -O schema_name=sec -O warehouse_id=1234567890abcdef \
     -O output_dir=detections rules/windows/
   ```

   Each selected parser produces one rule per Sigma rule, named `<rule_name>__<profile>`. Multiple
   rules are emitted as separate `---` documents in one file. With `-O output_dir=<dir>`, each rule
   is written to its own `<dir>/<rule_name>.yaml`, together with a `conversion_report.yaml` that
   lists what converted, what failed and why (see
   [Conversion report](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/discovery-and-reports.md#conversion-report)).
   Don't use the `--output-dir`/`-od` option of sigma-cli: it writes only the bare SQL condition of
   each rule, not the rule documents.

3. **Review and deploy the rules** (see [Deploying rules](#deploying-rules)). Converted rules are
   disabled by default, so they can be tested first.

### Lakewatch options

Options are passed as `-O key=value`.

| Option | Default | Meaning |
|--------|---------|---------|
| `parsers` | *(none)* | Comma-separated profile ids, for example `aws_cloudtrail,okta_system_log`. Without it, parser discovery runs instead of a conversion. |
| `table_name` | *(none)* | Table to read from. Use it when exactly one parser is selected. |
| `table_map` | *(none)* | `profile:table,profile:table` for several parsers. Every selected profile needs a table. |
| `catalog_name` | *(required)* | `catalog_name` of the rule, also used as `batch.sql.default_catalog_name` to resolve unqualified tables. Conversion fails if it's unset. |
| `schema_name` | *(required)* | `schema_name` of the rule, also used as `batch.sql.default_schema_name`. Conversion fails if it's unset. |
| `warehouse_id` | *(none)* | `batch.warehouse_id`: the SQL warehouse that runs the rule. The server rejects enabled batch rules without one, so conversion warns if it's unset. |
| `schedule` | `24h` | Rule schedule (Lakewatch duration). |
| `extend_lookback` | *(none)* | `timerange.extend_lookback`: widens the time window beyond the schedule. |
| `enabled` | `false` | `schedule.enabled`. Set `-O enabled=true` to schedule the rules immediately. |
| `default_fidelity` | *(from status)* | Override the rule fidelity. Accepts both `Investigative` and `FIDELITY_INVESTIGATIVE`. |
| `default_category` | `Static Signature` | Rule category. |
| `output_dir` | *(none)* | Write one file per rule, and `conversion_report.yaml`, into this directory. |
| `target` | `workspace` | `workspace` creates rules for the Lakewatch API, `content_pack` the rule documents of a Lakewatch content pack (see [Target modes](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/lakewatch-output.md#target-modes)). |
| `overrides` | *(none)* | YAML file with per-rule alert `summary`, `context` and `select` settings (see [Alert summaries](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/lakewatch-output.md#alert-summaries)). |
| `lakewatch_profiles_dir` | *(none)* | Directory with your own `*.yml` profiles. They are added to the built-in ones, and an id replaces a built-in id (see [Writing profiles](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/writing-profiles.md)). |
| `lakewatch_schemas` | *(none)* | JSON file with additional parser schemas, in the format of the bundled catalog. |
| `raw_log_field` | *(none)* | STRING column searched by keyword (unbound) searches, for every selected profile. |

Sigma metadata maps to the rule: `title` becomes the alert summary, `description` the description
and objective, `level` the severity, `attack.*` tags the MITRE entries, and `falsepositives` the
runbook. Sigma `stable` rules get `FIDELITY_INVESTIGATIVE`, and all others `FIDELITY_DEVELOPMENT`.
The full mapping is in
[Lakewatch rule output](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/lakewatch-output.md#rule-metadata).
Only batch rules are generated (streaming is future work).

### Supported parsers

Built-in profiles cover these Lakewatch parsers:

* **Cloud:** AWS CloudTrail, Okta, Azure (audit, sign-in, activity, Identity Protection),
  Microsoft 365 audit (general, Azure AD, Exchange), GCP Cloud Audit Logs, Google Workspace.
* **Web servers and proxies:** Cloudflare, GCP HTTP load balancer, Akamai WAF, AWS WAF, Zscaler ZIA,
  Cisco Umbrella.
* **EDR:** CrowdStrike FDR, SentinelOne Deep Visibility, Carbon Black Cloud.
* **Windows event logs:** Sysmon, Security, PowerShell and other channels. Most of these profiles
  need the custom Windows parsers, which aren't Lakewatch built-ins yet.

See [Built-in profiles](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/built-in-profiles.md)
for the profile ids, the logsources they match, and their limitations. To support another parser,
write your own profile (see
[Writing profiles](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/writing-profiles.md)).

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

Common flags:

| Flag | Meaning |
|------|---------|
| `--profile PROFILE` | Databricks CLI profile. Default: the SDK's standard auth chain. |
| `--dry-run` | Validate and print the planned changes; write nothing. |
| `--validate-only` | Validate the rules that would be written; write nothing. |
| `--warehouse-id ID` | Warehouse for the SQL dry run of the server-side validation. |
| `--catalog C`, `--schema S` | Deploy into another catalog or schema than the one in the files. |
| `--force` | Overwrite rules that were not made from this Sigma rule. |
| `--json` | Print the result as JSON. |

Redeploying is safe: a rule is updated only if it was made from the same Sigma rule, unchanged
rules are left alone, `schedule.enabled` is kept, and nothing is ever deleted. Creating or updating
a rule starts a one-time run of it on the server. See
[Deploying rules](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/deploying.md)
for all flags, the output format and the exit codes.

## Plain SQL output

The `default`, `dbsql` and `detection_yaml` formats produce Spark SQL `WHERE` conditions, with no
parser profile:

```bash
sigma convert -t databricks rules/windows/process_creation/proc_creation_win_whoami_execution.yml
sigma convert -t databricks -f dbsql -p snake_case rules/windows/
```

### CIDR Matching

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

### Unbound Keyword Search

Sigma rules with unbound keywords (values without field names) search the raw log line. By
default, the backend looks for keywords in a field named `raw` (`raw_data` when the target is
OCSF). Set another field with `-O raw_log_field=message`, or
`DatabricksBackend(raw_log_field="message")`. With `-f lakewatch`, each profile defines its own raw
event (see
[Keyword search and routing](https://github.com/alexott/pySigma-backend-databricks/blob/main/docs/writing-profiles.md#keyword-search-and-routing)).

```yaml
detection:
    selection:
        EventID: 4688
    keywords:
        - 'mimikatz'
        - '|re': '.*evil(cmd|powershell).*'
    condition: selection and keywords
```

Generates: `EventID = 4688 AND (contains(lower(raw), 'mimikatz') OR raw rlike '.*evil(cmd|powershell).*')`

Keywords in a list are ORed, and `'|all'` ANDs them. Wildcards turn into `contains()`
(`*malware*`), `startswith()` (`cmd.exe*`) or `endswith()` (`*.dll`).

## Maintainer

This backend is currently maintained by:

* [Alex Ott](https://github.com/alexott/)
