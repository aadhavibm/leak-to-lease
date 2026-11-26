# Verification evidence

[verification.json](verification.json) records the current test counts and
scoped live checks. It contains no credentials, machine names or absolute local
paths. It distinguishes an executed check from an external prerequisite that
was unavailable.

## Current checks

- 232 offline Python tests passed. The normal run skips three opt-in live tests.
- All three live tests were executed separately: database lifecycle, actual
  stdio MCP transport, and TLS/AppRole maximum-TTL/outage recovery.
- 92 Java tests and five Node timezone tests passed.
- The six-service replay accepted the original credential, verified application
  reads and a new visit, rotated the root credential, observed MySQL error 1045
  for the original value, and verified application work again.
- With 45-second maximum database leases and 105 seconds of traffic, each data
  service completed 192 operations and used three different database users.
  The run recorded no normal-rollover failures. After a 25-second Vault pause,
  readiness/new work failed closed and recovered without restarting services.
- A fresh synthetic-only local-parser check measured two findings before
  sanitization and none afterward. This was not a Vault Radar scan.

Timed acceptance was rerun with host idle sleep prevented. Earlier attempts
affected by host suspension were not counted as passes.

## Historical Vault Radar reports

[radar-before.json](radar-before.json) is NDJSON with two sanitized historical
findings: the shared configuration and PetClinic README. Its line numbers are
historical, not current remediation instructions. Hostnames, personal paths and
credential/file hashes were removed.

[radar-after.json](radar-after.json) is empty, the scanner's historical
zero-findings output. These files do not establish that the current tree is
clean or that a credential is rejected by MySQL.

The fresh Radar rerun could not authenticate because private HCP configuration
was unavailable. Fresh Bob-service orchestration was also blocked by its HTTP
525 response. Neither was substituted with a mocked success.
