"""Typed contracts used by dashboard, playbooks, audit, and reporting flows."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


def _as_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


@dataclass
class AuditEvent:
    timestamp: str
    event_type: str
    payload: dict[str, Any] = field(default_factory=dict)

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def model_validate(cls, value: dict[str, Any]) -> "AuditEvent":
        if not isinstance(value, dict):
            raise ValueError("AuditEvent must be a dict")
        return cls(
            timestamp=str(value.get("timestamp", "")),
            event_type=str(value.get("event_type", "")),
            payload=value.get("payload", {}) if isinstance(value.get("payload", {}), dict) else {},
        )


@dataclass
class SessionSummary:
    id: str
    caption: str
    start: str
    end: str
    event_count: int = 0
    tools: list[str] = field(default_factory=list)
    report_count: int = 0
    chat_turn_count: int = 0

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReportReference:
    path: str
    relative_path: str = ""
    modified: str = ""
    size_bytes: int = 0

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlaybookStep:
    id: str
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    retries: int = 0
    timeout_seconds: int = 300
    on_failure: str = "stop"

    @classmethod
    def model_validate(cls, value: dict[str, Any]) -> "PlaybookStep":
        if not isinstance(value, dict):
            raise ValueError("PlaybookStep must be a dict")
        on_failure = str(value.get("on_failure", "stop")).strip().lower() or "stop"
        if on_failure not in {"stop", "continue"}:
            raise ValueError("PlaybookStep.on_failure must be 'stop' or 'continue'")
        return cls(
            id=str(value.get("id", "")).strip(),
            tool=str(value.get("tool", "")).strip(),
            args=value.get("args", {}) if isinstance(value.get("args", {}), dict) else {},
            depends_on=_as_string_list(value.get("depends_on", [])),
            retries=int(value.get("retries", 0) or 0),
            timeout_seconds=max(1, int(value.get("timeout_seconds", 300) or 300)),
            on_failure=on_failure,
        )

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlaybookMetadata:
    name: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    owner: str = "local"
    source: str = "dashboard"
    updated_at: str = ""
    version: int = 1

    @classmethod
    def model_validate(cls, value: dict[str, Any]) -> "PlaybookMetadata":
        if not isinstance(value, dict):
            raise ValueError("PlaybookMetadata must be a dict")
        return cls(
            name=str(value.get("name", "")).strip(),
            description=str(value.get("description", "")).strip(),
            tags=_as_string_list(value.get("tags", [])),
            owner=str(value.get("owner", "local")).strip() or "local",
            source=str(value.get("source", "dashboard")).strip() or "dashboard",
            updated_at=str(value.get("updated_at", "")).strip(),
            version=max(1, int(value.get("version", 1) or 1)),
        )

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlaybookInputSpec:
    target: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def model_validate(cls, value: dict[str, Any] | None) -> "PlaybookInputSpec":
        if not isinstance(value, dict):
            return cls()
        return cls(
            target=str(value.get("target", "")).strip(),
            extra=value.get("extra", {}) if isinstance(value.get("extra", {}), dict) else {},
        )

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlaybookDefinition:
    metadata: PlaybookMetadata
    inputs: PlaybookInputSpec = field(default_factory=PlaybookInputSpec)
    steps: list[PlaybookStep] = field(default_factory=list)
    retry_policy: dict[str, Any] = field(default_factory=dict)
    guardrails: dict[str, Any] = field(default_factory=dict)
    output_contract: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def model_validate(cls, value: dict[str, Any]) -> "PlaybookDefinition":
        if not isinstance(value, dict):
            raise ValueError("PlaybookDefinition must be a dict")
        metadata = PlaybookMetadata.model_validate(value.get("metadata", {}))
        if not metadata.name:
            raise ValueError("metadata.name is required")
        raw_steps = value.get("steps", [])
        if not isinstance(raw_steps, list):
            raise ValueError("steps must be a list")
        steps = [PlaybookStep.model_validate(step) for step in raw_steps]
        for step in steps:
            if not step.id:
                raise ValueError("each step.id is required")
            if not step.tool:
                raise ValueError(f"step '{step.id}' tool is required")
        return cls(
            metadata=metadata,
            inputs=PlaybookInputSpec.model_validate(value.get("inputs", {})),
            steps=steps,
            retry_policy=value.get("retry_policy", {}) if isinstance(value.get("retry_policy", {}), dict) else {},
            guardrails=value.get("guardrails", {}) if isinstance(value.get("guardrails", {}), dict) else {},
            output_contract=value.get("output_contract", {}) if isinstance(value.get("output_contract", {}), dict) else {},
        )

    def model_dump(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.model_dump(),
            "inputs": self.inputs.model_dump(),
            "steps": [step.model_dump() for step in self.steps],
            "retry_policy": dict(self.retry_policy),
            "guardrails": dict(self.guardrails),
            "output_contract": dict(self.output_contract),
        }


@dataclass
class PlaybookValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    normalized: PlaybookDefinition | None = None

    def model_dump(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "normalized": self.normalized.model_dump() if self.normalized else None,
        }


@dataclass
class PlaybookRunStepResult:
    step_id: str
    tool: str
    success: bool
    elapsed_seconds: float = 0.0
    output: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlaybookRunResult:
    run_id: str
    playbook: str
    target: str
    status: str
    started_at: str
    ended_at: str
    steps: list[PlaybookRunStepResult] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)

    def model_dump(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "playbook": self.playbook,
            "target": self.target,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "steps": [step.model_dump() for step in self.steps],
            "artifacts": list(self.artifacts),
        }


@dataclass
class CloudTriageResult:
    provider: str
    target: str
    command: str
    success: bool
    stdout: str = ""
    stderr: str = ""
    acquired_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    evidence_meta: dict[str, Any] = field(default_factory=dict)

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MemoryPipelineResult:
    image_path: str
    profile: str
    plugins: list[str] = field(default_factory=list)
    iocs: list[dict[str, Any]] = field(default_factory=list)
    suspicious_processes: list[dict[str, Any]] = field(default_factory=list)
    suspicious_network: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    confidence_notes: list[str] = field(default_factory=list)

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutiveCitation:
    source: str
    quote: str = ""
    event_type: str = ""
    timestamp: str = ""

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutiveSummarySection:
    title: str
    content: str
    citations: list[ExecutiveCitation] = field(default_factory=list)

    def model_dump(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "content": self.content,
            "citations": [citation.model_dump() for citation in self.citations],
        }


@dataclass
class ExecutiveSummaryReport:
    session_id: str
    generated_at: str
    context: ExecutiveSummarySection
    key_findings: ExecutiveSummarySection
    business_impact: ExecutiveSummarySection
    mitre_mapping: ExecutiveSummarySection
    recommendations: ExecutiveSummarySection
    confidence_and_limitations: ExecutiveSummarySection

    def model_dump(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "generated_at": self.generated_at,
            "context": self.context.model_dump(),
            "key_findings": self.key_findings.model_dump(),
            "business_impact": self.business_impact.model_dump(),
            "mitre_mapping": self.mitre_mapping.model_dump(),
            "recommendations": self.recommendations.model_dump(),
            "confidence_and_limitations": self.confidence_and_limitations.model_dump(),
        }
