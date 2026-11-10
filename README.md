# Secure Endpoint (AMP) Events and Audit Logs Add-on for Cisco

Splunk add-on `TA-cisco-secure-endpoint`, version 1.0.0.

Collects Cisco Secure Endpoint (AMP for Endpoints) events, audit logs, compromises, computers, vulnerabilities and top malware threats from the Secure Endpoint API, each selectable with its own schedule. Event types, audit log types and groups are picked from lists read live from the API (all, only selected, all except selected). Events use sourcetype cisco:se in the Cisco Security Cloud app's format; audit logs use cisco:se:audit with CIM mappings. Not affiliated with Cisco.

## Layout

- `TA-cisco-secure-endpoint/`: the app exactly as shipped to Splunkbase (unpacked from the release package)
- `tools/package.py`: builds the Splunkbase package and runs offline AppInspect-style checks
- `docs/`: Splunkbase listing text and screenshots

## Build

```
python3 tools/package.py TA-cisco-secure-endpoint dist --vendor cisco
```

Good: `RESULT: OK`. Then AppInspect:

```
splunk-appinspect inspect dist/TA-cisco-secure-endpoint-<version>.tgz --mode precert --included-tags cloud
```

## Releases

Each version is tagged `v<version>`. Its GitHub release has the exact package uploaded to
Splunkbase attached, with its md5.

## License

Apache-2.0. Independent project, not affiliated with or endorsed by Cisco.
