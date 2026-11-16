"""Filter evaluation and single-event match detection engine."""

import ipaddress
import re
from functools import lru_cache
from typing import Any

from sentinellog.models import Alert, Event, EvidenceRef
from sentinellog.rules.schema import Rule

BASE_SEVERITY_SCORES = {
    "info": 10,
    "low": 30,
    "medium": 50,
    "high": 70,
    "critical": 90,
}


@lru_cache(maxsize=1024)
def _compile_regex(pattern: str) -> re.Pattern[str]:
    """Cache compiled regular expressions."""
    return re.compile(pattern)


def evaluate_filter_operator(field_val: Any, operator: str, target_val: Any) -> bool:
    """Evaluate a single filter operator against an event field value."""
    if operator == "exists":
        exists = field_val is not None and field_val != ""
        return exists is bool(target_val)

    # For other operators, if field_val is None, it cannot match
    if field_val is None:
        return False

    if operator == "exact":
        # Handle string or numeric equality
        if isinstance(field_val, int) and isinstance(target_val, str) and target_val.isdigit():
            return field_val == int(target_val)
        return (
            str(field_val).lower() == str(target_val).lower()
            if isinstance(target_val, str)
            else field_val == target_val
        )

    if operator == "in":
        if not isinstance(target_val, (list, tuple, set)):
            return False
        # String case-insensitive comparison if strings
        str_val = str(field_val).lower()
        target_strs = {str(item).lower() for item in target_val}
        return str_val in target_strs or field_val in target_val

    if operator == "contains":
        return str(target_val) in str(field_val)

    if operator == "icontains":
        return str(target_val).lower() in str(field_val).lower()

    if operator == "regex":
        rx = _compile_regex(str(target_val))
        return bool(rx.search(str(field_val)))

    if operator == "cidr":
        try:
            ip = ipaddress.ip_address(str(field_val))
            if isinstance(target_val, list):
                return any(ip in ipaddress.ip_network(str(net), strict=False) for net in target_val)
            network = ipaddress.ip_network(str(target_val), strict=False)
            return ip in network
        except ValueError:
            return False

    if operator == "gte":
        try:
            return float(field_val) >= float(target_val)
        except (ValueError, TypeError):
            return False

    if operator == "lte":
        try:
            return float(field_val) <= float(target_val)
        except (ValueError, TypeError):
            return False

    if operator == "intel":
        from sentinellog.enrich.intel import get_threat_intel_feed

        feed = get_threat_intel_feed()
        is_blocked = feed.is_blocked(str(field_val))
        return is_blocked is bool(target_val)

    return False


def matches_filter(event: Event, filter_spec: dict[str, Any]) -> bool:
    """Check if an Event matches all conditions specified in a filter dictionary (AND logic)."""
    for raw_key, target_val in filter_spec.items():
        if "__" in raw_key:
            field_name, operator = raw_key.rsplit("__", 1)
        else:
            field_name = raw_key
            operator = "exact"

        field_val = getattr(event, field_name, None)
        if not evaluate_filter_operator(field_val, operator, target_val):
            return False

    return True


def matches_exceptions(event: Event, exceptions: dict[str, Any]) -> bool:
    """Check if an Event matches any exception suppression rule (OR logic)."""
    if not exceptions:
        return False

    for raw_key, target_val in exceptions.items():
        # Handle formats like src_ip_in: [10.0.0.5] or src_ip__in
        if "__" in raw_key:
            field_name, operator = raw_key.rsplit("__", 1)
        elif raw_key.endswith("_in"):
            field_name = raw_key[:-3]
            operator = "in"
        else:
            field_name = raw_key
            operator = "exact"

        field_val = getattr(event, field_name, None)
        if evaluate_filter_operator(field_val, operator, target_val):
            return True

    return False


def matches_allowlist(event: Event, allowlist: dict[str, Any]) -> bool:
    """Check if an event matches global allowlist rules."""
    if not allowlist:
        return False

    # 1. Trusted IPs
    trusted = allowlist.get("trusted_ips", [])
    if event.src_ip:
        for entry in trusted:
            if isinstance(entry, dict) and entry.get("ip") == event.src_ip:
                return True
            if isinstance(entry, str) and entry == event.src_ip:
                return True

    # 2. Vulnerability Scanners
    scanners = allowlist.get("vulnerability_scanners", [])
    if event.src_ip:
        for entry in scanners:
            if isinstance(entry, dict) and entry.get("ip") == event.src_ip:
                return True
            if isinstance(entry, str) and entry == event.src_ip:
                return True

    # 3. Service Accounts
    svc_accounts = allowlist.get("service_accounts", [])
    if event.user:
        for entry in svc_accounts:
            if isinstance(entry, dict) and entry.get("user") == event.user:
                return True
            if isinstance(entry, str) and entry == event.user:
                return True

    return False


class MatchEngine:
    """Engine for evaluating single-event match detection rules."""

    def evaluate(self, rule: Rule, event: Event) -> Alert | None:
        """Evaluate a match rule against an Event and return an Alert if matched."""
        if rule.type != "match":
            return None

        # Check log_source compatibility
        if rule.log_source != "any" and rule.log_source != event.source_type:
            return None

        # Check exceptions
        if matches_exceptions(event, rule.exceptions):
            return None

        # Check filter
        if not matches_filter(event, rule.detection.filter):
            return None

        # Extract entities
        entities: dict[str, list[str]] = {}
        if event.src_ip:
            entities["src_ip"] = [event.src_ip]
        if event.user:
            entities["user"] = [event.user]
        if event.host:
            entities["host"] = [event.host]

        score = BASE_SEVERITY_SCORES.get(rule.severity.value, 50)
        first_iso = event.timestamp.isoformat()

        explanation = (
            f"{rule.name}: matching event from {entities} at {first_iso}. {rule.description}"
        )

        evidence = [EvidenceRef(file=event.file, line_number=event.line_number, raw=event.raw)]

        return Alert(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            score=score,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            count=1,
            entities=entities,
            evidence=evidence,
            mitre={"tactic": rule.mitre.tactic, "technique": rule.mitre.technique},
            explanation=explanation,
            recommended_action=rule.response.recommended_action,
        )
