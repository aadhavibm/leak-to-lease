# Leak-to-Lease Remediation Runbook

Use the [README quick start](../README.md#quick-start) to replay the workflow on
fresh resources. The Bob collection contribution is a separate deliverable;
this repository supplies its MCP backend and application demonstration.
This checklist does not grant approval to change an existing environment.

The [README quick start](../README.md#quick-start) provides an isolated replay.
It uses Docker Compose for fresh MySQL/Vault instances and runs the existing
PetClinic jars locally. The explicit `--allow-disposable-changes` flag approves
only that run's new resources. Tracked credential sources are copied before
quarantine; only those private copies are modified. Successful runs stop their
Java processes and remove their own Compose stack. Failures retain owner-only
diagnostic files outside the repository and still attempt resource cleanup.

## Before changes

- Identify the application, change owner, MySQL endpoint/account, Vault endpoint,
  `secret` KV mount, database mount/connection, roles and recovery plan.
- Use fresh scanner metadata: approved absolute source path, current one-based
  line and compatible SHA-256 fingerprint when available. Never use historical
  line numbers or read a credential file into Bob.
- Verify all seven MCP tools are attached. Missing tools or missing authentication
  are blockers, not reasons to simulate success.
- Run the same approved gate before and after; record whether real Radar or the
  local backend parser ran. A finding is exit `1`; scan errors are exit `2`.

## Approved quarantine and role setup

1. Obtain file/Vault/database scope approval.
2. Quarantine the finding at mount `secret`; require
   `QUARANTINED_AND_SANITIZED`. If available, pass the approved compatible
   `expected_fingerprint`.
3. On `QUARANTINED_NOT_SANITIZED`, retain safe recovery metadata and stop. A
   concurrent edit, already-sanitized line or unsupported format must not be
   overwritten or retried blindly.
4. Enable the approved database mount and verify any existing mount's type.
5. Configure its MySQL connection using the returned quarantine reference and
   literal `{{username}}`/`{{password}}` placeholders.
6. Create the approved roles/SQL/TTLs. Review the default `%` and `localhost`
   root-rotation statements rather than assuming those accounts are correct.
7. Confirm the original credential is accepted before rotation, server-side.

## Migration before rotation

- Prepare schema/data separately as administrator. The app's dynamic users have
  DML privileges and cannot seed their own tables.
- For disposable setup only, the explicitly acknowledged owned-container
  `reset-demo.sh --seed-only` command initializes data without reinjecting
  credentials into tracked sources.
- Supply separate role-scoped application authentication privately.
- Start Config Server, Discovery, Customers, Vets, Visits, and Gateway in order.
- Wait for health and discovery-backed route readiness. Verify real application
  database reads/writes, not only actuator responses or a degraded owner aggregate.
- Inspect each application lease: require `ACTIVE` and positive TTL.
- Keep optional Admin/GenAI/paid-provider behavior separate from this six-service
  acceptance path.

## Separately approved rotation and proof

1. Obtain administrator-rotation approval after migration checks pass.
2. Call `rotate_root` exactly once for the intended connection/mount.
3. Call `prove_dead` for each quarantine reference using the original endpoint,
   schema and username.
4. Require `REJECTED`, `connection_rejected=true`, error `1045`, and
   `CREDENTIAL_PROVEN_DEAD`. `INCONCLUSIVE_DB_UNREACHABLE` is not a pass.
5. Recheck all downstream reads/writes and gateway behavior. PetClinic signals
   Visits degradation with `visitsUnavailable=true`; treat it as a failure of
   full application verification, even though owner data remains available.
6. Run the same gate and require exit `0`. Do not disable the gate to make it pass.
7. Verify automatic credential/pool rollover beyond maximum TTL under actual
   database traffic. The bundled pool blocks new SQL after an unusable lease,
   marks readiness down, and retries recovery without service restart. Cached
   responses and already-running transactions are not forcibly cancelled.

## Handoff

Report safe references/fingerprints, changed locations/roles, actual test and scan
results, failed or untested stages, retained resources and recovery actions.
Do not restore the leaked password as an automatic rollback. Stop only owned
disposable resources after verification; stopping Vault dev destroys its storage.

Replay-only credential reinjection requires its own explicit acknowledgement
and must never be used against an existing application or as a recovery step.
