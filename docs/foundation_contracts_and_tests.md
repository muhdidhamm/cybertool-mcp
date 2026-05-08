# Foundation Contracts and Regression Tests

## Typed contract baseline

Implemented in `tools/contracts.py`:

- Audit/session interfaces (`AuditEvent`, `SessionSummary`)
- Reporting interfaces (`ReportReference`, `ExecutiveSummaryReport`)
- Playbook interfaces (`PlaybookDefinition`, `PlaybookRunResult`, validation/result models)
- Cloud and memory normalized evidence contracts

## Regression tests

Implemented under `tests/`:

- `test_contracts.py` validates core contract instantiation.
- `test_playbooks.py` validates playbook schema checks, CRUD, clone/delete, and runtime execution.
- `test_reporting.py` validates executive summary pipeline behavior for unknown sessions.

## Why this baseline matters

- Prevents schema drift while dashboard/playbook/reporting APIs evolve.
- Establishes a test harness before broader feature expansion.
- Keeps audit/session/reporting/playbook interfaces explicit and versionable.
