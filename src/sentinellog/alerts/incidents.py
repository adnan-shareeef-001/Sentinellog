"""Correlation of related alerts into multi-stage security incidents."""

from collections import defaultdict
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from sentinellog.models import Alert, Severity


class Incident(BaseModel):
    """Correlated cluster of security alerts targeting a shared entity."""

    id: str
    title: str
    severity: Severity
    score: int
    status: str = "open"  # open | investigating | resolved | false_positive
    first_seen: datetime
    last_seen: datetime
    primary_entity: str
    alert_count: int
    alert_ids: list[str] = Field(default_factory=list)
    alerts: list[Alert] = Field(default_factory=list)
    entities: dict[str, list[str]] = Field(default_factory=dict)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert incident to dictionary for serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "score": self.score,
            "status": self.status,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "primary_entity": self.primary_entity,
            "alert_count": self.alert_count,
            "alert_ids": self.alert_ids,
            "entities": self.entities,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
        }


def _extract_primary_entity(alert: Alert) -> str:
    """Select the most specific anchor entity (host > user > src_ip)."""
    if "host" in alert.entities and alert.entities["host"]:
        return f"host:{alert.entities['host'][0]}"
    if "user" in alert.entities and alert.entities["user"]:
        return f"user:{alert.entities['user'][0]}"
    if "src_ip" in alert.entities and alert.entities["src_ip"]:
        return f"ip:{alert.entities['src_ip'][0]}"
    return "entity:unspecified"


def correlate_incidents(alerts: list[Alert], window_seconds: int = 1800) -> list[Incident]:
    """Group correlated alerts sharing an anchor entity within time window into Incidents."""
    if not alerts:
        return []

    # Sort alerts chronologically
    sorted_alerts = sorted(alerts, key=lambda a: a.first_seen)

    # Group by primary entity
    entity_buckets: dict[str, list[Alert]] = defaultdict(list)
    for a in sorted_alerts:
        p_ent = _extract_primary_entity(a)
        entity_buckets[p_ent].append(a)

    incidents: list[Incident] = []
    inc_counter = 1

    for p_ent, b_alerts in entity_buckets.items():
        # Split into clusters based on time window
        current_cluster: list[Alert] = []

        for a in b_alerts:
            if not current_cluster:
                current_cluster.append(a)
            else:
                last_time = current_cluster[-1].last_seen
                if (a.first_seen - last_time).total_seconds() <= window_seconds:
                    current_cluster.append(a)
                else:
                    incidents.append(_build_incident(current_cluster, inc_counter, p_ent))
                    inc_counter += 1
                    current_cluster = [a]

        if current_cluster:
            incidents.append(_build_incident(current_cluster, inc_counter, p_ent))
            inc_counter += 1

    return sorted(incidents, key=lambda inc: inc.first_seen)


def _build_incident(cluster: list[Alert], index: int, primary_entity: str) -> Incident:
    """Aggregate a cluster of alerts into an Incident model."""
    inc_id = f"INC-{cluster[0].first_seen.strftime('%Y%m%d')}-{index:04d}"

    # Determine highest severity
    severities = [a.severity for a in cluster]
    if Severity.CRITICAL in severities:
        top_sev = Severity.CRITICAL
    elif Severity.HIGH in severities:
        top_sev = Severity.HIGH
    elif Severity.MEDIUM in severities:
        top_sev = Severity.MEDIUM
    else:
        top_sev = Severity.LOW

    top_score = max(a.score for a in cluster)
    first_seen = min(a.first_seen for a in cluster)
    last_seen = max(a.last_seen for a in cluster)

    # Merge entities
    merged_entities: dict[str, list[str]] = defaultdict(list)
    mitre_tactics: set[str] = set()
    mitre_techs: set[str] = set()

    for a in cluster:
        for k, vals in a.entities.items():
            merged_entities[k].extend(vals)
        if a.mitre.get("tactic"):
            mitre_tactics.add(a.mitre["tactic"])
        if a.mitre.get("technique"):
            mitre_techs.add(a.mitre["technique"])

    cleaned_entities = {k: sorted(set(v)) for k, v in merged_entities.items()}

    rule_names = {a.rule_name for a in cluster}
    if len(rule_names) == 1:
        title = f"{next(iter(rule_names))} on {primary_entity}"
    else:
        title = f"Multi-vector threat activity against {primary_entity} ({len(cluster)} alerts)"

    return Incident(
        id=inc_id,
        title=title,
        severity=top_sev,
        score=top_score,
        first_seen=first_seen,
        last_seen=last_seen,
        primary_entity=primary_entity,
        alert_count=len(cluster),
        alert_ids=[f"{a.rule_id}@{a.first_seen.isoformat()}" for a in cluster],
        alerts=cluster,
        entities=cleaned_entities,
        mitre_tactics=sorted(mitre_tactics),
        mitre_techniques=sorted(mitre_techs),
    )
