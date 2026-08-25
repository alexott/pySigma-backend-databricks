# Improvements wanted in `pySigma-pipeline-ocsf` to support backend mappings

Notes for [SigmaHQ/pySigma-pipeline-ocsf](https://github.com/SigmaHQ/pySigma-pipeline-ocsf),
gathered while building the Lakewatch output format in this backend (which consumes the
pipeline's output to pick an OCSF gold table and emit a rule). They are ordered by how much
they unblock a backend that must derive the target table/class from the normalized rule.

All observations are against `sigma/pipelines/ocsf/ocsf.py` as of 2026-08.

---

## The core problem

The pipeline conveys the OCSF class **only implicitly**, as a detection *condition* injected by
`AddConditionTransformation` (e.g. it ANDs `type_uid = 100701` into the rule). A backend that
needs to know "which OCSF class/table is this rule about" has to:

1. walk the transformed rule's detection items,
2. find a `class_uid` / `type_uid` / `class_name` item,
3. and reverse-derive the class (`class_uid = type_uid // 100`, or normalize the class name).

That works, but it is fragile and indirect — the backend is parsing something meant as a query
predicate to recover a structural fact the pipeline already knew.

### P1.1 — Expose the OCSF class as a structured rule attribute (not only a condition)

In addition to (or instead of) injecting the predicate, set a first-class attribute the backend
can read directly — e.g. via `SetStateTransformation` (`pipeline.state["ocsf_class_uid"]`) or a
`rule.custom_attributes["ocsf_class_uid"] / ["ocsf_class_name"]`. Then a backend reads one value
instead of walking detection items and dividing by 100.

```python
# alongside the AddConditionTransformation for each category
ProcessingItem(
    identifier=f"ocsf_state_{log_source}",
    transformation=SetStateTransformation("ocsf_class_uid", class_uid),
    rule_conditions=[LogsourceCondition(category=log_source)],
)
```

### P1.2 — Always emit `class_uid` (consistently), not a mix of keys

Today the injected key varies by category:

| Category | Injected key |
|----------|--------------|
| `dns`, `dns_query`, `firewall`, `network_connection` | `class_uid` |
| `application`, `antivirus`, `registry_event` | `class_uid` (+ sometimes `category_uid`) |
| `process_creation`, `file_event`, `registry_add`, … | `type_uid` only |
| `proxy` | `class_name` ("HTTP Activity") only |

A backend has to handle all three shapes. Emitting `class_uid` for **every** mapping (keeping
`type_uid`/`activity_id` as an *additional* refinement where useful) removes the `// 100`
derivation and the class-name normalization path entirely.

---

## P2 — Correctness of the emitted UIDs

### P2.1 — Fix malformed `type_uid` values

Some values don't satisfy the OCSF rule `type_uid = class_uid * 100 + activity_id`:

- Windows Security `4624`/`4625` → `type_uid: 3002001`. Authentication is class `3002`, so a valid
  type_uid is `300201`/`300202`. `3002001 // 100 = 30020`, which is **not a valid class_uid** — a
  backend deriving the class gets garbage.
- `4697` / system `7045` → `type_uid: 20100401` (six/eight-digit values that don't resolve to a
  standard class).

These break any `type_uid // 100` derivation. Emit the correct `class_uid` (e.g. `3002` for the
auth events) and, if wanted, a correct `type_uid`.

### P2.2 — Map to OCSF classes that actually exist (and that have data)

Several categories point at classes with no clear OCSF gold-table home, or at a surprising class:

- `application` → `class_uid: 6002` (Application Lifecycle) — rarely a real detection table.
- `registry_*` → `class_uid: 201001` / various — not a standard 4-digit OCSF class.
- `antivirus` → `class_uid: 2004` (Detection Finding) — arguably correct, but worth confirming it
  is the intended class rather than a Malware/Threat class.

A backend can only resolve a table for classes that exist in the target schema; today the Windows
endpoint categories that map to registry/service/app-lifecycle classes silently fall through to a
manual override. Documenting the intended class per category (and picking classes with real
tables) would make coverage predictable.

### P2.3 — Be consistent about `actor.process.*` vs `process.*`

Field targets mix the two roles:

- `process_creation`: `Image → process.name`, `ParentImage → process.parent_process.name`.
- `network_connection`: `Image → actor.process.file.name`, `ParentImage →
  actor.process.parent_process.file.name`.

For the *created/target* process the OCSF `process.*` branch is right; for the *initiating* actor
it is `actor.process.*`. Pick per class deliberately and consistently — a backend (and the gold
table) distinguishes them, so an inconsistent mapping produces predicates against the wrong column.

Relatedly, `Image → process.name` vs `process.file.name`/`process.file.path`: `process.name` is
the process name, while the executable path usually belongs in `process.file.name`/`.path`. Align
with the OCSF 1.x attribute for whichever the source field actually is.

---

## P3 — Field-mapping completeness

### P3.1 — Remove identity/no-op mappings

Many entries map a field to itself, which normalizes nothing and just hides the gap:

- `process_access`: `GrantedAccess → GrantedAccess`, `Provider_Name → Provider_Name`,
  `CallTrace → CallTrace`, `SourceUser → SourceUser`.
- `pipe_created`: `Image → Image`, `PipeName → PipeName`.
- `image_load`: `Company → Company`, `Signature → Signature`, `Product → Product`, …
- The first `proxy` item (`ocsf_field_mappings_proxy`) maps `c-uri → c-uri`, `cs-method →
  cs-method`, … while a *second* item (`ocsf_field_mappings_logsource_proxy`) maps the same fields
  to real OCSF paths (`http_request.url.url_string`, `http_request.http_method`, …). The identity
  one is redundant and, applied first, can be confusing.

Either complete these to real OCSF attribute paths or drop them so it's clear the field is
unmapped.

### P3.2 — Normalize *values*, not just field names

The pipeline renames fields but (except `event_code → str`) doesn't normalize values. Detections
that filter on, e.g., `status = 'Success'`, `EventType`, logon type, or an antivirus disposition
need the source value mapped to the OCSF normalized value/`*_id`. Without this, a rule converted
against an OCSF gold table filters on the raw source string, which may not match the normalized
column. Value maps (or `ConvertTypeTransformation`/replacements) for the common outcome/status
fields would close this.

---

## P4 — Coverage: cloud / IAM / SaaS categories

The pipeline currently covers Windows/endpoint Sigma categories (process, file, registry, network,
dns, proxy, webserver, ps_*). It has **no** mappings for cloud/SaaS audit sources (AWS CloudTrail,
Azure, GCP, Okta, M365, GWorkspace, Kubernetes audit, …).

Those sources map to exactly the OCSF classes with the richest detection tables — `authentication`
(3002), `api_activity` (6003), `account_change` (3001), `entity_management` (3004),
`group_management` (3006), `user_access` (3005), `datastore_activity` (6004). A backend that
resolves tables by class can already target all of them; the blocker is that the pipeline never
produces those classes. Adding logsource mappings for cloud categories (Sigma `product: aws`/
`azure`/`gcp`/`okta`/`m365` with the relevant `service`/`category`) → these IAM/API classes would
unlock the most valuable detections.

---

## P5 — Pipeline hygiene

### P5.1 — Duplicate `ProcessingItem` identifiers

Four items share `identifier="ocsf_field_mappings_windows_system"` (the eventid-7045 mapping, the
general windows-system mapping, and two that actually target `ps_script` / `ps_module`
categories). Duplicate identifiers undermine `processing_item_applied` tracking and make pipelines
hard to debug/override. Give each a unique, accurate identifier (the two PowerShell ones are also
mislabeled as "windows_system").

### P5.2 — Consider populating `allowed_backends` / priority docs

`allowed_backends=frozenset()` (all backends) is fine, but documenting the expected downstream
contract — "this pipeline injects `class_uid`; backends should read state key X" — would let
backend authors rely on a stated interface instead of reverse-engineering the transforms.

---

## Summary — what unblocks the most, fastest

1. **P1.1 / P1.2**: expose `class_uid` as a structured attribute, consistently for every category.
   This alone removes all the fragile table-derivation logic in downstream backends.
2. **P2.1 / P2.2**: fix the malformed `type_uid`s and point categories at real OCSF classes.
3. **P4**: add cloud/IAM/SaaS category mappings — that's where the high-value detection tables are.
4. **P3 / P5**: complete field/value mappings and clean up duplicate identifiers.
