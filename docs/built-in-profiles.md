# Built-in Lakewatch profiles

The backend ships one profile per supported Lakewatch parser. Select them with
`-O parsers=<id>,<id>`, or run [parser discovery](discovery-and-reports.md#parser-discovery) to
find the ones that fit your rules. Each section below lists the known limitations of a group of
profiles. To write your own profile, see [Writing profiles](writing-profiles.md).

## Profiles

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

## Azure

The Azure profiles convert most SigmaHQ `cloud/azure` rules. PIM alerts (`service: pim`) have no
Lakewatch parser, so they stay unmatched. Sign-in `Status` isn't mapped (the diagnostic `status`
is `{errorCode, additionalDetails}`), `ActivityDetails` doesn't exist, and sign-in
`properties.message` is unsupported (the Graph `signIn` object has no `message`, so it would never match). Array fields
(`targetResources`, `additionalDetails`, `networkLocationDetails`) map to the whole `properties`
column and support only `|contains`, matched approximately against the JSON text. Rules that use
them with any other comparison fail. `contains` searches the whole `properties` JSON, so it can
also match text outside the named array.

## Microsoft 365

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

## Google Cloud and Google Workspace

The GCP profiles map Cloud Audit Logs (`gcp_audit_log`) and the Google Workspace Admin SDK Reports
`activities` resource (`google_workspace_reports`). In `google_workspace_reports`, the service fields
(`eventService` and `protoPayload.serviceName`) go through a value map: `admin.googleapis.com` becomes `admin` and
`login.googleapis.com` becomes `login`, and any other service value fails to convert. In `gcp_audit_log`, the service
name passes through unchanged. Of the `data.protoPayload.*` names, only `data.protoPayload.serviceName`,
`.methodName`, `.logName` and `.resource.type` are mapped (there is no
`data.protoPayload.*` prefix), and any other `data.protoPayload.<x>` fails as not mapped. A trailing `*` in
`gcp.audit.method_name` renders `startswith()`. The declared arrays inside `protoPayload`
(`authorizationInfo`, for example `data.protoPayload.authorizationInfo.permission` and `.granted`) match any
element, rendered as `exists(try_variant_get(...), x0 -> ...)`. Each condition gets its own `exists()`, so
`permission` and `granted` of one rule may be satisfied by different elements. In `google_workspace_reports`, `setting_name` and
`new_value` map to the `SETTING_NAME` and `NEW_VALUE` entries of `parameters` through `entries`
(`new_value` takes `value`, or `boolValue` as a string). Workspace rules (`service: google_workspace.*`) route only to `google_workspace_reports`, because the
same events in `gcp_audit_log` sit in an array inside a VARIANT. The SigmaHQ `cloud/gcp` rules go from 0/26 to 25/26
convertible; the one that fails (`gcp_breakglass_container_workload_deployed`) uses keyword searches, and its `logName` values
never equal a full `projects/<p>/logs/...` name.

## Web servers and proxies

The web profiles cover the `category: webserver` rules (Cloudflare, GCP load balancer, Akamai and AWS WAF)
and the `category: proxy` rules (Zscaler ZIA and Cisco Umbrella). A rule converts per profile, so use
`sigma convert -s` (collect errors) to get a query for every profile that has all the rule's fields; without it, the
first profile that lacks a field aborts the rule. Keyword searches (a detection with no field) fail on every web
profile except Zscaler, because no raw event is configured to search. The mappings follow the vendors' log field references and
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
  in the allowlist (see `modifiers` in [Writing profiles](writing-profiles.md#value-transforms)). A `|re` anchored at the start (`^/admin`, or `^https?://` on Zscaler, whose `url` has no scheme)
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
- **Zscaler.** `event` is a VARIANT that holds the complete vendor event payload. Only the whole column is mapped,
  member access isn't, and it is matched only as a whole value with `|contains`. Keyword searches run over
  `to_json(event)`; they are approximate and raise a `UserWarning` (see
  [Keyword search and routing](writing-profiles.md#keyword-search-and-routing)).
- **Akamai caveats.** `httpMessage.query` is logged URL-encoded, so values with raw special characters may not
  match, and many SigmaHQ rules list both forms. Akamai logs only requests that triggered a security rule, so rules
  see a subset of the traffic. `httpMessage.status` is a STRING column.
- **Umbrella `cs-host`.** `cs-host` maps to `serverName`, the destination server. `hostName` is mapped only under
  its own name.

## Windows event logs

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

## CrowdStrike Falcon Data Replicator

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

## SentinelOne Deep Visibility

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

## Carbon Black Cloud

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
