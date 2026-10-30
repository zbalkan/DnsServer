# Log Exporter App

Exports DNS query log entries to File, HTTP, and Syslog targets.

## Configuration

The app is configured using `dnsApp.config` (JSON).

- `labels` (optional): A dictionary of static key/value labels to enrich every exported query event. For example: `"labels": { "environment": "production", "site": "tallinn" }`. Output JSON contains the separate `labels` field; Syslog properties use the `label_` prefix.
- `enableEdnsLogging`: Include the EDNS extended-error information when available. This is independent of structured blocking metadata.
- `blockingMetadata`: Populated only when the DNS server's `logQueryMetadata` setting is enabled and a blocking decision supplied metadata. It remains separate from static `labels` and the response classification `responseType`.

See the shipped `dnsApp.config` for the remaining export target settings.
