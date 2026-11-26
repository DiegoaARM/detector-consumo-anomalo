from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from . import config

Label = Literal["normal", "legitimate_growth", "suspicious", "inconclusive"]
Severity = Literal["info", "low", "medium", "high"]
Profile = Literal["workstation", "server", "development"]


class ProcessInfo(BaseModel):
    """Read-only details of one process at one sample."""

    pid: int
    name: str
    cpu: float = 0.0
    memory: float = 0.0
    exe: str = ""
    cmdline: str = ""
    parent_pid: int | None = None
    parent_name: str = ""
    created_at: datetime | None = None
    external_ips: list[str] = Field(default_factory=list)


class Sample(BaseModel):
    """One telemetry point. Rates are bytes/second, percentages are 0-100."""

    ts: datetime
    cpu: float = Field(ge=0, le=100)
    memory: float = Field(ge=0, le=100)
    net_out_rate: float = Field(ge=0)
    net_in_rate: float = Field(ge=0)
    disk_write_rate: float = Field(ge=0)
    process_count: int = Field(ge=0)
    top_processes: dict[str, float] = Field(default_factory=dict)
    processes: list[ProcessInfo] = Field(default_factory=list)
    external_ips: list[str] = Field(default_factory=list)
    run_key_names: list[str] = Field(default_factory=list)
    run_key_values: dict[str, str] = Field(default_factory=dict)
    scheduled_task_count: int = 0
    scheduled_task_names: list[str] = Field(default_factory=list)


class ActivityEvent(BaseModel):
    ts: datetime
    type: str
    detail: str = ""
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    expected_processes: list[str] = Field(default_factory=list)


class Collection(BaseModel):
    samples: list[Sample]
    events: list[ActivityEvent] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class AnalyzeRequest(BaseModel):
    source: Literal["scenario", "local"] = "scenario"
    scenario: str | None = None
    profile: Profile = config.DEFAULT_PROFILE
    baseline_seconds: int = Field(
        default=config.DEFAULT_BASELINE_SECONDS,
        ge=config.MIN_SCAN_SECONDS,
        le=config.MAX_SCAN_SECONDS,
    )
    window_seconds: int = Field(
        default=config.DEFAULT_WINDOW_SECONDS,
        ge=config.MIN_SCAN_SECONDS,
        le=config.MAX_SCAN_SECONDS,
    )
    note: str | None = None


class EventRequest(BaseModel):
    type: str = Field(min_length=2, max_length=40)
    detail: str = Field(default="", max_length=200)
    duration_minutes: int | None = Field(default=5, ge=1, le=1440)
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    expected_processes: list[str] = Field(default_factory=list)


class MonitorRequest(BaseModel):
    interval_seconds: int = Field(
        default=config.MONITOR_DEFAULT_INTERVAL_SECONDS, ge=10, le=3600
    )
    duration_minutes: int = Field(
        default=config.MONITOR_DEFAULT_DURATION_MINUTES, ge=1, le=180
    )


class Signal(BaseModel):
    name: str
    label: str
    baseline: float
    current: float
    delta_pct: float
    unit: str = "%"  # "" means an absolute count, not a percentage


class SeriesPoint(BaseModel):
    ts: datetime
    cpu: float
    memory: float
    net_out_rate: float


class ProcessFinding(BaseModel):
    pid: int
    name: str
    cpu: float
    exe: str = ""
    cmdline: str = ""
    parent: str = ""
    external_ips: list[str] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)
    expected: bool = False
    expected_by: str = ""


class PersistenceFinding(BaseModel):
    kind: Literal["run_key", "scheduled_task"]
    name: str
    value: str = ""


class HistoryBaseline(BaseModel):
    used: bool
    sample_count: int
    window_days: int
    cpu_p95: float
    net_out_p95: float
    process_count_mean: float
    cpu_vs_p95_pct: float
    net_vs_p95_pct: float
    note: str


class AnalysisResult(BaseModel):
    id: str
    created_at: datetime
    source: str
    scenario: str
    profile: str = config.DEFAULT_PROFILE
    label: Label
    label_es: str
    severity: Severity
    confidence: float
    anomaly_score: float
    headline: str
    summary: str
    signals: list[Signal]
    context_notes: list[str] = Field(default_factory=list)
    evidence_legitimate: list[str]
    evidence_suspicious: list[str]
    verifications: list[str]
    caveat: str
    series: list[SeriesPoint]
    activity_events: list[ActivityEvent]
    process_findings: list[ProcessFinding] = Field(default_factory=list)
    persistence_findings: list[PersistenceFinding] = Field(default_factory=list)
    history_baseline: HistoryBaseline | None = None
    warnings: list[str]
    model: str
    llm_used: bool
    persisted: bool = False
