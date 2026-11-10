[cisco_secure_endpoint://<name>]
* One input per Cisco Secure Endpoint organization (account). <name>: letters, digits, '.', '_' or '-'
  (max 64), starting with a letter or digit.
* Created and edited in Splunk Web: the add-on's Inputs page (or Settings > Data inputs).
* Splunk starts the input every minute (interval = 60). Each run collects the data types that are due,
  each on its own schedule (<type>_every, in minutes). "Run now" on the Inputs page collects them all at once.
* Sourcetypes: cisco:se (events, compromises, computers, vulnerabilities, top malware threats, with
  EndpointDataType as the Cisco Security Cloud app writes it) and cisco:se:audit (audit logs).
  host = the account name.
* Checkpoints: $SPLUNK_HOME/var/lib/splunk/modinputs/cisco_secure_endpoint/<name>.json.
  Log: $SPLUNK_HOME/var/log/splunk/cisco_se_<name>.log (index _internal, sourcetype cisco:se:ta:log).
* Each data type of an account should be collected by one input only; the Inputs page refuses a second
  input that collects the same data type from the same account.

account = <string>
* Name of the Secure Endpoint account (API host, client ID, API key, optional proxy) saved on the
  add-on's Inputs page. Required.

collect_events = <boolean>
* Events (/v1/events): detections, quarantines, scans, isolation, updates, faults, ... Default 1.

events_every = <integer>
* Minutes between event collections (1-1440). Default 5.

collect_audit = <boolean>
* Audit logs (/v1/audit_logs): console sign-ins and changes to policies, groups, exclusions, users,
  computers, isolation sessions, ... Sourcetype cisco:se:audit. Default 1.

audit_every = <integer>
* Minutes between audit log collections (1-1440). Default 5.

collect_compromises = <boolean>
* Compromises (/v1/compromises): new or changed ones only (status, updated_at). Default 0.

compromises_every = <integer>
* Minutes between compromise collections (5-10080). Default 60.

collect_metrics = <boolean>
* Top malware threats (/v1/metrics/top_malware_threats): one event per collection. Default 0.

metrics_every = <integer>
* Minutes between top malware threat collections (5-10080). Default 60.

collect_computers = <boolean>
* Computers (/v1/computers): one event per computer per collection (an inventory snapshot). Default 0.

computers_every = <integer>
* Minutes between computer snapshots (60-10080). Default 1440 (daily).

collect_vulnerabilities = <boolean>
* Vulnerabilities (/v1/vulnerabilities): one event per entry per collection (a snapshot). Default 0.

vulnerabilities_every = <integer>
* Minutes between vulnerability snapshots (60-10080). Default 1440 (daily).

event_types_mode = all|only|except
* all: every event type, including types Cisco adds later. only: the types in event_types.
  except: every type except those in event_types. Default all.

event_types = <comma-separated list>
* Event type IDs (from /v1/event_types), e.g. 1090519054,553648143.

audit_types_mode = all|only|except
* Audit log types to collect, as event_types_mode. Default all.

audit_types = <comma-separated list>
* Audit log type IDs (from /v1/audit_log_types), e.g. Computer,Policy.

groups_mode = all|only|except
* Groups whose events, computers and vulnerabilities are collected, as event_types_mode. Default all.

groups = <comma-separated list>
* Group GUIDs (from /v1/groups).

start_hours_ago = <integer>
* How far back the first collection of events and audit logs starts (0-720). Default 24.

overlap_minutes = <integer>
* Each event collection starts this long before the newest event already collected, so events that
  reach the cloud late are still collected; events already sent are skipped by id (0-1440). Default 60.

audit_overlap_minutes = <integer>
* Each audit window starts this long before the previous one ended; records already sent are skipped
  (0-1440). Default 10.

audit_delay_minutes = <integer>
* Audit windows end this long before now (0-120). Default 2.

page_size = <integer>
* Records per API call (1-500). Default 500.

log_level = DEBUG|INFO|WARNING|ERROR
* Default INFO.
