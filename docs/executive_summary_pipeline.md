# Executive Summary Session-Synthesis Pipeline

## Goal

Generate an evidence-backed executive summary from a single session timeline while minimizing hallucination risk.

## Data sources

- Audit events (`tool.invoke/result/error`, `command.*`, `session.*`)
- Saved chat turns
- Linked report artifacts

## Output schema

`ExecutiveSummaryReport` sections:

- `context`
- `key_findings`
- `business_impact`
- `mitre_mapping`
- `recommendations`
- `confidence_and_limitations`

Each section carries a citation list (`source`, `event_type`, `timestamp`, `quote`).

## Guardrails

- Redaction patterns remove credentials/tokens/key material.
- Citation-first generation: every section includes evidence references.
- Confidence section explicitly reports missing evidence and failure counts.

## Integration points

- Exposed as `generate_executive_summary_from_session(session_id)`.
- Compatible with report designer and playbook run artifacts.
