# Log Exporter App

Exports DNS query log entries, including optional structured blocking provenance, to File, HTTP, and Syslog targets.

## Configuration

The app is configured using `dnsApp.config` (JSON).

- `enableEdnsLogging`: Include the EDNS extended-error information when available. This is independent of structured blocking metadata.

See the shipped `dnsApp.config` for the remaining export target settings.
