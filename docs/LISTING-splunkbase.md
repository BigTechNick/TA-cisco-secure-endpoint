# Splunkbase listing - Secure Endpoint (AMP) Events and Audit Logs Add-on for Cisco

Package: TA-cisco-secure-endpoint-1.0.0.tgz (md5 5c6026a238e0f2fd7df7070f01658415)
Name: Secure Endpoint (AMP) Events and Audit Logs Add-on for Cisco
Category: Security, Fraud & Compliance
Platform: Splunk Enterprise 9.x and 10.x (incl. 10.7), Splunk Cloud Platform
CIM: Authentication, Change. License: Apache 2.0. Support: community, best effort.
Screenshots: cisco-se-1-inputs.png, cisco-se-2-add-input.png, cisco-se-3-edit-input.png (synthetic data)

## Short description
Collects Cisco Secure Endpoint (AMP for Endpoints) events, audit logs, compromises, computers, vulnerabilities and top malware threats from the API. Event types, audit log types and groups are picked from live lists. Same cisco:se format as the Cisco Security Cloud app; audit logs CIM-mapped. Not affiliated with Cisco.

## Release notes 1.0.0
First release.
- Events, audit logs, compromises, top malware threats, computers and vulnerabilities, each a checkbox with its own schedule.
- Event types, audit log types and groups loaded live from the API: All (includes ones added later), Only selected, All except selected.
- cisco:se in the Cisco Security Cloud app's format (API JSON + EndpointDataType + group names).
- cisco:se:audit with CIM mappings (Authentication, Change).
- Checkpoints with overlap and duplicate removal, rate-limit back-off, Run now, proxy support, Status dashboard.

## AppInspect 1.0.0 (cloud tags)
0 failures, 0 errors. Warnings, no action needed: check_for_splunk_js (Inputs page uses SplunkJS, telemetry notice),
check_for_python_script_existence (Python 3 only), check_for_modular_inputs (one modular input, cisco_secure_endpoint).

## Details (Splunkbase Details tab)
## What it collects

Each data type is a checkbox on the input, with its own schedule.

| Data type | Secure Endpoint API | Sourcetype | Default |
|---|---|---|---|
| Events: detections, quarantines, scans, isolation, updates, faults | `/v1/events` | `cisco:se` | on, every 5 min |
| Audit logs: console sign-ins; changes to policies, groups, exclusions, users, computers, isolation | `/v1/audit_logs` | `cisco:se:audit` | on, every 5 min |
| Compromises (new or changed only) | `/v1/compromises` | `cisco:se` | off, hourly |
| Top malware threats | `/v1/metrics/top_malware_threats` | `cisco:se` | off, hourly |
| Computers (inventory snapshot) | `/v1/computers` | `cisco:se` | off, daily |
| Vulnerabilities (snapshot) | `/v1/vulnerabilities` | `cisco:se` | off, daily |

## Why this add-on

* **Lists that stay current.** Event types, audit log types and groups are picked on the Inputs page from lists read live from the API, as a searchable multi-select with three modes: **All** (includes types and groups added later), **Only selected** and **All except selected**. Nothing has to be set up again when Secure Endpoint changes.
* **Same event format as the Cisco Security Cloud app.** `cisco:se` events are the API's JSON plus `EndpointDataType` (`events`, `compromises`, `computers`, `vulnerabilities`, `metrics_top_malware_threats`); events also carry `groups` (GUID and name). Where the Cisco Security Cloud app is installed, its field extractions and CIM mappings for `cisco:se` apply, and existing searches keep working.
* **Audit logs with CIM mappings** (`cisco:se:audit`).

## Where to install

| Splunk instance | Install? | Why |
|---|---|---|
| Heavy forwarder | Yes | Runs the input and parses the data. |
| Search heads (including Splunk Cloud and Enterprise Security) | Yes | Audit log CIM mappings, event types and tags, JSON fields, Status dashboard. Do not configure inputs there. |
| Indexers | No | The heavy forwarder parses the data. |

## Set up

1. In the Secure Endpoint console: **Administration > Organization Settings > Configure API Credentials > New API Credential**, scope **Read-only**. Keep the client ID and API key.
2. Create the index the input will write to (the add-on creates no indexes).
3. On the heavy forwarder, open the add-on > **Inputs** > **Add account**: a name (it becomes the data's `host`), the API host of your region, the client ID and API key, and a proxy only if needed. Saving tests the credential: *Events: OK; Audit logs: OK*. The credential is stored encrypted in Splunk's credential store.
   * North America: `api.amp.cisco.com`
   * Europe: `api.eu.amp.cisco.com`
   * Asia Pacific, Japan and China: `api.apjc.amp.cisco.com`
4. **Add input**: name, account, index, the data types and how often, and the filters for event types, audit log types and groups. One input per Secure Endpoint organization.
5. Check the input's status on the Inputs page, or the **Status** dashboard.

Outbound HTTPS (443) from the forwarder to the API host is needed.

## How collection works

* Splunk starts the input every minute; each run collects the data types that are due. **Run now** collects every selected type at once.
* **Events**: the first run starts *First run: hours back* (default 24). Later runs start from the newest event already collected minus an overlap (default 60 minutes), for events that reach the cloud late; events already sent are skipped by ID. With *Only selected*, the event types and groups are passed to the API.
* **Audit logs**: read in windows of up to one hour, overlapping the previous window (default 10 minutes); records already sent are skipped.
* **Compromises**: only new or changed ones are written. **Computers** and **vulnerabilities**: every record each time (`_time` = collection time). **Top malware threats**: one event per collection.
* Rate limits (HTTP 429) and temporary errors are retried with back-off. A failed data type is tried again within 15 minutes and does not stop the others.
* Checkpoints are saved as it goes: after a restart or an error, the next run continues from them.

## CIM mapping (`cisco:se:audit`)

| Event type | Records | CIM data model | Tags |
|---|---|---|---|
| `cisco_se_authentication` | console sign-ins | Authentication | authentication |
| `cisco_se_account_change` | users, API credentials | Change (Account_Management) | change, account |
| `cisco_se_endpoint_change` | computers, isolation, scans, fetched files, endpoint IOC scans | Change (Endpoint_Changes) | change, endpoint |
| `cisco_se_config_change` | policies, groups, exclusions, detections and other settings | Change | change |

Main fields: `vendor_product`, `app`, `action`, `status`, `user`, `src_user`, `dest`, `object`, `object_id`, `object_category`, `object_attrs`, `change_type`, `signature`, `result`.

`cisco:se` uses `KV_MODE = json`; its CIM mappings come from the Cisco Security Cloud app where installed.

## Example searches

```
index=<your index> sourcetype="cisco:se" EndpointDataType=events | stats count by event_type | sort - count
index=<your index> sourcetype="cisco:se:audit" | stats count by audit_log_type event
index=<your index> sourcetype="cisco:se:audit" tag=authentication | stats count by user action
```

## Logs

One line per data type per collection, and one per run, in `$SPLUNK_HOME/var/log/splunk/cisco_se_<input>.log` (index `_internal`, sourcetype `cisco:se:ta:log`):

```
index=_internal sourcetype="cisco:se:ta:log" ("collected" OR "failed" OR "run done" OR "run failed")
```

* HTTP 401: wrong client ID or API key, or the credential was deleted.
* HTTP 403: the credential cannot read that data.
* HTTP 404 on every call: wrong API host (region).
* Cannot reach the API host: DNS, firewall or proxy; set the account's proxy if needed.

## Moving from the Cisco Security Cloud app's Secure Endpoint input

1. Add the account and an input here, with *First run: hours back* covering the time since that input last ran.
2. Disable the Cisco Security Cloud app's Secure Endpoint input, or the events are indexed twice. Its dashboards and CIM mappings keep working with this add-on's `cisco:se` data.

## Support

Community-supported, best effort, through this Splunkbase page. Independent project, not affiliated with or endorsed by Cisco. Cisco and Cisco Secure Endpoint are trademarks of Cisco Systems, Inc.
