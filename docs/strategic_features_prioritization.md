# Strategic Features Prioritization

## Priority order

1. **RBAC + SSO + tenancy isolation**
   - Highest risk reduction and compliance impact.
2. **Scheduler + continuous assessments**
   - Increases platform stickiness and recurring value.
3. **Findings correlation graph**
   - Reduces alert noise and enables attack-path context.
4. **Case integrations (Jira/ServiceNow/Linear)**
   - Improves triage-to-remediation workflow closure.
5. **Telemetry (cost/performance/noisy tools)**
   - Enables optimization and predictable operations.
6. **Plugin SDK**
   - Accelerates ecosystem and third-party contribution.

## Delivery sequencing

- **Wave 1:** RBAC/SSO, scheduler.
- **Wave 2:** correlation graph, case integrations.
- **Wave 3:** telemetry and plugin SDK hardening.

## KPI examples

- Mean-time-to-remediation (MTTR).
- False positive reduction for correlated findings.
- Scheduled playbook execution success rate.
- Per-tool cost and queue latency trends.
