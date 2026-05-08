# Cloud IR + Memory Pipeline Design

## Cloud triage adapters

- `cloud_triage_aws_ssm(instance_id, command, region)`:
  - Uses AWS SSM `send-command`.
  - Normalizes response into `CloudTriageResult`.
  - Emits structured evidence with provider metadata and persisted JSON artifact.
- `cloud_triage_azure_vm_run_command(resource_group, vm_name, command)`:
  - Uses Azure CLI `vm run-command invoke`.
  - Returns the same normalized evidence envelope as AWS.

## Memory pipeline

- `volatility3_memory_pipeline(memory_dump, profile, timeout_per_plugin)`:
  - Runs plugin chain (`windows.info`, `windows.pslist`, `windows.netscan`, `windows.cmdline`).
  - Extracts heuristic IOCs, suspicious process lines, and network indicators.
  - Produces a normalized `MemoryPipelineResult` object.

## Evidence normalization

- Every cloud/memory output includes:
  - acquisition timestamp,
  - source/provider identity,
  - raw command output,
  - normalized indicators for downstream reporting.

## Chain-of-custody hooks

- Artifacts are written to `output/` with deterministic names.
- Each run can be linked from playbook history and executive summary generation.
