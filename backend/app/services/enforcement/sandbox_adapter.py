"""
Sandbox Enforcement Adapter
===========================
Executes controlled active containment within an isolated, thread-safe in-memory
routing and filtering table without modifying host OS network or firewall settings.
"""

from datetime import datetime, timezone, timedelta
from threading import RLock
from typing import Any, Dict, List, Optional, Set, Tuple
from backend.app.schemas.policy import ActiveEnforcementRule, PolicyDecision
from backend.app.services.enforcement.base import EnforcementAdapter, EnforcementResult


class SandboxAdapter(EnforcementAdapter):
    """
    In-memory laboratory sandbox adapter.
    
    Distinction:
      - BLOCK: Completely drops all traffic from target_ip across all ports.
      - RESTRICT: Drops traffic from target_ip targeted ONLY at the restricted target_port,
                  or applies packet rate-limit constraints while allowing other traffic.
    """

    def __init__(self):
        self._lock = RLock()
        self._rules: Dict[str, ActiveEnforcementRule] = {}
        # Fast lookup sets
        self._blocked_ips: Set[str] = set()
        self._restricted_targets: Dict[str, Set[int]] = {}  # ip -> set of restricted ports
        self._rate_limited_ips: Dict[str, int] = {}         # ip -> max packets per window

    @property
    def mode_name(self) -> str:
        return "SANDBOX"

    def _rebuild_lookup_tables(self) -> None:
        """Rebuild quick lookup structures from active non-expired rules."""
        now = datetime.now(timezone.utc)
        self._blocked_ips.clear()
        self._restricted_targets.clear()
        self._rate_limited_ips.clear()

        for rule in self._rules.values():
            if rule.status == "ACTIVE" and rule.expires_at > now:
                if rule.action == "Block":
                    self._blocked_ips.add(rule.target_ip)
                elif rule.action == "Restrict":
                    if rule.target_port is not None:
                        if rule.target_ip not in self._restricted_targets:
                            self._restricted_targets[rule.target_ip] = set()
                        self._restricted_targets[rule.target_ip].add(rule.target_port)
                    else:
                        # Rate limit default cap (e.g. 10 packets)
                        self._rate_limited_ips[rule.target_ip] = 10

    def enforce(self, decision: PolicyDecision, rule_id: str) -> EnforcementResult:
        with self._lock:
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(seconds=decision.suggested_ttl_seconds)

            rule = ActiveEnforcementRule(
                rule_id=rule_id,
                event_id=decision.event_id,
                target_ip=decision.target_ip,
                target_port=decision.target_port,
                protocol=decision.protocol or "ANY",
                action=decision.policy_action,
                status="ACTIVE",
                mode=self.mode_name,
                reason=decision.reason,
                ttl_seconds=decision.suggested_ttl_seconds,
                expires_at=expires_at,
                remaining_ttl_seconds=decision.suggested_ttl_seconds,
                created_at=now,
            )

            self._rules[rule_id] = rule
            self._rebuild_lookup_tables()

            if decision.policy_action == "Block":
                msg = f"[SANDBOX] Host {decision.target_ip} quarantined. All subsequent traffic dropped."
            elif decision.policy_action == "Restrict":
                msg = f"[SANDBOX] Restriction applied to {decision.target_ip} on port {decision.target_port}."
            else:
                msg = f"[SANDBOX] Observational rule applied for {decision.target_ip}."

            return EnforcementResult(
                success=True,
                rule_id=rule_id,
                target_ip=decision.target_ip,
                target_port=decision.target_port,
                action=decision.policy_action,
                status="ACTIVE",
                mode=self.mode_name,
                message=msg,
                ttl_seconds=decision.suggested_ttl_seconds,
                expires_at=expires_at,
                metadata={"sandbox": True, "active_rules_count": len(self._rules)},
            )

    def revoke(self, rule_id: str, actor: str = "analyst") -> EnforcementResult:
        with self._lock:
            rule = self._rules.get(rule_id)
            if not rule:
                return EnforcementResult(
                    success=False,
                    rule_id=rule_id,
                    target_ip="0.0.0.0",
                    target_port=None,
                    action="Allow",
                    status="FAILED",
                    mode=self.mode_name,
                    message=f"Rule '{rule_id}' not found in sandbox table.",
                    ttl_seconds=0,
                    expires_at=datetime.now(timezone.utc),
                )

            now = datetime.now(timezone.utc)
            rule.status = "REVOKED"
            rule.revoked_at = now
            rule.revoked_by = actor
            self._rebuild_lookup_tables()

            return EnforcementResult(
                success=True,
                rule_id=rule_id,
                target_ip=rule.target_ip,
                target_port=rule.target_port,
                action=rule.action,
                status="REVOKED",
                mode=self.mode_name,
                message=f"[SANDBOX] Containment rule '{rule_id}' for {rule.target_ip} successfully revoked.",
                ttl_seconds=0,
                expires_at=now,
                metadata={"revoked_by": actor},
            )

    def list_active_rules(self) -> List[ActiveEnforcementRule]:
        with self._lock:
            now = datetime.now(timezone.utc)
            active: List[ActiveEnforcementRule] = []
            for rule in self._rules.values():
                if rule.status == "ACTIVE" and rule.expires_at > now:
                    rem = max(int((rule.expires_at - now).total_seconds()), 0)
                    rule.remaining_ttl_seconds = rem
                    active.append(rule)
            return sorted(active, key=lambda r: r.expires_at)

    def prune_expired(self) -> List[str]:
        with self._lock:
            now = datetime.now(timezone.utc)
            expired_ids: List[str] = []
            for rule_id, rule in list(self._rules.items()):
                if rule.status == "ACTIVE" and rule.expires_at <= now:
                    rule.status = "EXPIRED"
                    expired_ids.append(rule_id)

            if expired_ids:
                self._rebuild_lookup_tables()

            return expired_ids

    def is_traffic_allowed(
        self, source_ip: str, dst_port: int, packet_count: int = 1
    ) -> Tuple[bool, str]:
        """
        Evaluate incoming simulated traffic against the sandbox enforcement table.
        Returns: (is_allowed: bool, filter_reason: str)
        """
        with self._lock:
            self.prune_expired()

            # 1. Check Full IP Quarantine (BLOCK)
            if source_ip in self._blocked_ips:
                return False, f"SANDBOX_FILTER_DROP: Source IP {source_ip} is under active quarantine block."

            # 2. Check Port-Specific Restriction (RESTRICT)
            if source_ip in self._restricted_targets:
                restricted_ports = self._restricted_targets[source_ip]
                if dst_port in restricted_ports:
                    return False, f"SANDBOX_FILTER_DROP: Traffic to port {dst_port} restricted for {source_ip}."

            # 3. Check Volumetric Rate Limit (RESTRICT)
            if source_ip in self._rate_limited_ips:
                max_pkts = self._rate_limited_ips[source_ip]
                if packet_count > max_pkts:
                    return False, f"SANDBOX_FILTER_DROP: Volumetric limit ({max_pkts} pkts) exceeded for {source_ip}."

            return True, "SANDBOX_FILTER_ALLOW: No active containment rule matched."

    def health_check(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "status": "HEALTHY",
                "mode": self.mode_name,
                "active_quarantined_ips": list(self._blocked_ips),
                "restricted_port_targets": {k: list(v) for k, v in self._restricted_targets.items()},
                "total_managed_rules": len(self._rules),
            }
