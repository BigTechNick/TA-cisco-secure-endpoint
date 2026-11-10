# Secure Endpoint (AMP) Events and Audit Logs Add-on for Cisco

Version 1.0.0. App ID (folder name): `TA-cisco-secure-endpoint`.

Collects data from the Cisco Secure Endpoint API v1 (formerly AMP for
Endpoints). Each data type is a checkbox on the input, with its own schedule:

| Data type | API | Sourcetype | Default |
|---|---|---|---|
| Events (detections, quarantines, scans, isolation, updates, faults, ...) | `/v1/events` | `cisco:se` | on, every 5 min |
| Audit logs (console sign-ins; changes to policies, groups, exclusions, users, computers, isolation, ...) | `/v1/audit_logs` | `cisco:se:audit` | on, every 5 min |
| Compromises (new or changed only) | `/v1/compromises` | `cisco:se` | off, hourly |
| Top malware threats | `/v1/metrics/top_malware_threats` | `cisco:se` | off, hourly |
| Computers (inventory snapshot) | `/v1/computers` | `cisco:se` | off, daily |
| Vulnerabilities (snapshot) | `/v1/vulnerabilities` | `cisco:se` | off, daily |

> Independent project, not affiliated with or endorsed by Cisco. Cisco and
> Cisco Secure Endpoint are trademarks of Cisco Systems, Inc. See NOTICE.

## Why this add-on

* **Lists that stay current.** Event types, audit log types and groups are
  picked on the Inputs page from lists read live from the API, as a
  searchable multi-select with three modes: **All** (includes types and
  groups Cisco or your administrators add later), **Only selected**, and
  **All except selected**. Nothing has to be set up again when Secure
  Endpoint changes.
* **Same event format as the Cisco Security Cloud app.** `cisco:se` events
  are the API's JSON plus `EndpointDataType` (`events`, `compromises`,
  `computers`, `vulnerabilities`, `metrics_top_malware_threats`), and events
  also carry `groups` (GUID and name). Where the Cisco Security Cloud app is
  installed on the search heads, its field extractions and CIM mappings for
  `cisco:se` apply to this add-on's data, and existing searches keep working.
* **Audit logs with CIM mappings** (`cisco:se:audit`), which the Cisco app
  does not collect.

Everything is managed in Splunk Web:

* **Inputs** page: Secure Endpoint accounts (API host, client ID and API key,
  optional proxy; stored encrypted in Splunk's credential store; a *Test*
  button checks the credential against events and audit logs) and the
  inputs that use them: add, edit, enable/disable, run now, delete. Status
  per data type (last collection, records written, errors) is shown next to
  each input.
* **Status** dashboard: collections per data type, records written, minutes
  behind, errors grouped, what reached the index and how late, Splunk's own
  messages about the input, and changes made on the Inputs page.

## Install

| Where | What it does there |
|---|---|
| Heavy forwarder (or the instance that runs inputs) | Runs the input. Required. |
| Search heads | Audit log CIM mappings, event types and tags, `cisco:se` JSON fields, collector log fields for the Status dashboard. |
| Indexers | Nothing needed (data is parsed on the heavy forwarder). |

Splunk Enterprise 9.x and 10.x, Splunk Cloud Platform (Victoria). Python 3
(3.9 or 3.13). No other add-ons are needed. Restart Splunk after installing
on a heavy forwarder.

The index the input writes to must exist on the indexers.

## Set up

1. **API credential.** In the Secure Endpoint console: *Administration >
   Organization Settings > Configure API Credentials > New API Credential*,
   scope **Read-only**. Keep the *3rd Party API Client ID* and *API Key*.
2. **Account.** On the add-on's *Inputs* page, *Add account*: a name (it
   becomes the data's `host` field), the API host of your region, the client
   ID and API key, and a proxy if this forwarder needs one.
   * North America: `api.amp.cisco.com`
   * Europe: `api.eu.amp.cisco.com`
   * Asia Pacific, Japan and China: `api.apjc.amp.cisco.com`
3. **Input.** *Add input*: the account, the index, the data types to collect
   and how often, and the filters (event types, audit log types, groups).
   One input per Secure Endpoint organization; the page refuses a second
   input that collects the same data type from the same account, which would
   index it twice.

Outbound HTTPS (443) from the forwarder to the API host is needed.

## How collection works

* Splunk starts the input every minute; each run collects the data types
  that are due. *Run now* collects every selected type at once.
* **Events** start `start_hours_ago` back (default 24 h) on the first run,
  then each run reads from the newest event already collected minus an
  overlap (default 60 min), for events that reach the cloud late; events
  already sent are skipped by ID. With *Only selected*, the event types and
  groups are passed to the API, so only those are read.
* **Audit logs** are read in windows of up to one hour, ending a little before
  now (default 2 min) and overlapping the previous window (default 10 min).
  Records already sent are skipped (the API's audit log IDs are not unique,
  so the record itself is compared).
* **Compromises**: only new or changed ones (status or `updated_at`) are
  written.
* **Computers** and **vulnerabilities** are snapshots: every record, each
  time (`_time` = collection time).
* **Top malware threats**: one event per collection.
* Rate limits (HTTP 429, `X-RateLimit-*` headers) and temporary errors are
  retried with back-off. A failed data type is tried again within 15 minutes
  and does not stop the others.
* Checkpoints: `$SPLUNK_HOME/var/lib/splunk/modinputs/cisco_secure_endpoint/<input>.json`.
  Deleting an input removes its checkpoint.

## Data

`host` is the account name. `source` is `cisco_secure_endpoint://<input>`.

### `cisco:se`

The API record as JSON (field names as Cisco returns them), plus
`EndpointDataType`; events also have `groups` (`guid`, `name`). `_time` is the
event's timestamp (with milliseconds), the compromise's `updated_at` (or `created_at`), or the
collection time for snapshots and top malware threats.

### `cisco:se:audit`

The API record as JSON (`event`, `audit_log_type`, `audit_log_id`,
`audit_log_user`, `created_at`, `item`, `message`, `old_attributes`,
`new_attributes`). `_time` is `created_at`.

CIM mappings:

| Records | Data model | Tags |
|---|---|---|
| Sign-ins (`sso_login` and other login events) | Authentication | `authentication` |
| `User`, `ApiCredential` changes | Change: Account_Management | `change`, `account` |
| `Computer`, `IsolationSession`, `ScanRequest`, `FetchedFile`, `OpenIocScan` | Change: Endpoint_Changes | `change`, `endpoint` |
| Everything else (policies, groups, exclusions, detections, ...) | Change | `change` |

Fields: `vendor`, `product`, `vendor_product`, `app`, `dvc` (= host), `action`
(`success`/`failure` for sign-ins; `created`, `modified`, `deleted`, `stopped`
for changes), `status`, `result`, `signature`, `change_type`, `object`
(`item`), `object_id`, `object_category` (`audit_log_type` in snake case),
`object_attrs` (attribute names in `old_attributes` / `new_attributes`),
`user` (who signed in; the account changed; or the administrator), `src_user`
(the administrator, for account changes), `dest` (the computer for endpoint
changes), `description`.

Event types: `cisco_se_audit`, `cisco_se_authentication`,
`cisco_se_account_change`, `cisco_se_endpoint_change`, `cisco_se_config_change`.

## Logs and troubleshooting

* Collector log: `$SPLUNK_HOME/var/log/splunk/cisco_se_<input>.log`
  (index `_internal`, sourcetype `cisco:se:ta:log`). One line per data type
  per collection, e.g.
  `collected events: written 412, duplicates 37, excluded 0, pages 2, api calls 3, newest 1.2 min ago, 2.4 s`,
  and one `run done` / `run failed` line per run.
* Inputs page actions: `cisco_se-webapi.log` (sourcetype `cisco:se:ta:webapi`).
* Set *Log level* to DEBUG in the input's advanced settings for API calls.
* `401`: client ID or API key wrong, or the credential was deleted.
  `403`: the credential cannot read that data. `404` on every call: wrong API
  host (region).

## Settings reference

See `README/inputs.conf.spec`.

## Release notes

### 1.0.0

* First release: events, audit logs, compromises, computers, vulnerabilities
  and top malware threats; live lists with All / Only selected / All except
  selected for event types, audit log types and groups; per data type
  schedules; `cisco:se` in the Cisco Security Cloud app's format;
  `cisco:se:audit` with CIM mappings; Inputs page and Status dashboard.

## Support

Community support through Splunkbase (questions and issues on the app's
page). Licensed under Apache 2.0.
