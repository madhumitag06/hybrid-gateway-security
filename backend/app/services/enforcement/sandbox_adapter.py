"""
Sandbox Enforcement Adapter
===========================
Executes controlled active containment within an isolated, thread-safe in-memory
routing and filtering table without modifying host OS network or firewall settings.
"""

from datetime import datetime, timezone, timedelta
import ipaddress
import json
from threading import RLock
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.request
import urllib.error
from backend.app.config import settings
from backend.app.schemas.policy import ActiveEnforcementRule, PolicyDecision
from backend.app.services.enforcement.base import EnforcementAdapter, EnforcementResult


PROTECTED_GATEWAY_IPS = {
    "10.10.10.1",
    "10.10.10.2",
    "10.20.10.1",
    "10.20.10.2",
    "10.30.10.1",
    "10.30.10.2",
    "10.30.10.5",
    "10.30.10.10",
    "10.30.10.15",
    "10.30.10.20",
}


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

    def _is_valid_lab_target(self, ip_str: str) -> bool:
        """
        Safety guardrail: Ensures optional lab router enforcement only ever targets
        explicitly configured isolated lab workload IPs (10.10.10.0/24 or 10.20.10.0/24),
        never gateway interfaces, loopback, management plane, or external/host networks.
        """
        if not ip_str or ip_str in PROTECTED_GATEWAY_IPS:
            return False
        try:
            target = ipaddress.ip_address(ip_str.strip())
            if target.is_loopback or target.is_multicast or target.is_unspecified:
                return False
            allowed_cidrs = getattr(settings, "lab_allowed_target_cidrs", ["10.10.10.0/24", "10.20.10.0/24"])
            in_lab_subnet = False
            for cidr in allowed_cidrs:
                if target in ipaddress.ip_network(str(cidr).strip(), strict=False):
                    in_lab_subnet = True
                    break
            if not in_lab_subnet:
                return False
            for allow_cidr in getattr(settings, "management_allowlist", []):
                if target in ipaddress.ip_network(str(allow_cidr).strip(), strict=False):
                    return False
            return True
        except ValueError:
            return False

    def _sync_to_lab_router(
        self,
        operation: str,
        rule_id: str,
        target_ip: str,
        action: str,
        target_port: Optional[int] = None,
        protocol: str = "TCP",
        ttl_seconds: int = 300,
    ) -> Tuple[bool, str]:
        """
        If LAB_ENFORCEMENT_ENABLED=true is explicitly opted-in, synchronizes the containment rule
        with the isolated virtual router container (lab-router) on the internal management network.
        Never modifies Windows host firewall or host routing tables.
        """
        if not getattr(settings, "lab_enforcement_enabled", False):
            return False, "Optional lab data-plane enforcement is disabled (default sandbox mode)."

        if operation.upper() == "ADD" and ttl_seconds <= 0:
            return False, "Rule TTL is non-positive; router sync skipped."

        if not self._is_valid_lab_target(target_ip):
            return False, f"Target IP {target_ip} is outside isolated lab workload subnets; router sync skipped."

        router_url = getattr(settings, "lab_router_url", "http://10.30.10.2:8099").rstrip("/")
        # Safety check: never send control requests to localhost/loopback
        if "localhost" in router_url.lower() or "127.0.0.1" in router_url or "::1" in router_url:
            return False, "Refusing router sync to loopback address."

        endpoint = f"{router_url}/api/firewall/rules"
        payload = json.dumps({
            "operation": operation,
            "rule_id": rule_id,
            "target_ip": target_ip,
            "action": action,
            "target_port": target_port,
            "protocol": protocol,
            "ttl_seconds": ttl_seconds,
        }).encode("utf-8")

        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if 200 <= resp.status < 300:
                    return True, "Synchronized with isolated lab-router FORWARD firewall chain."
                return False, f"lab-router returned HTTP {resp.status}."
        except Exception as exc:
            return False, f"lab-router unreachable ({exc}); retained in-memory sandbox containment."

    @staticmethod
    def _canonical_spec(target_ip: str, action: str, target_port: Optional[int]) -> Tuple[str, str, Optional[int]]:
        eff_port = (
            None
            if action == "Block"
            else (int(target_port) if target_port is not None and int(target_port) > 0 else 8080)
        )
        return (target_ip.strip(), action, eff_port)

    def _is_spec_referenced(
        self, spec_tuple: Tuple[str, str, Optional[int]], now: Optional[datetime] = None
    ) -> bool:
        check_now = now or datetime.now(timezone.utc)
        for r in self._rules.values():
            if r.status == "ACTIVE" and r.expires_at > check_now:
                if self._canonical_spec(r.target_ip, r.action, r.target_port) == spec_tuple:
                    return True
        return False

    def clear_in_memory(self) -> None:
        with self._lock:
            self._rules.clear()
            self._blocked_ips.clear()
            self._restricted_targets.clear()
            self._rate_limited_ips.clear()

    def enforce(self, decision: PolicyDecision, rule_id: str) -> EnforcementResult:
        with self._lock:
            now = datetime.now(timezone.utc)
            if decision.policy_action not in ("Block", "Restrict") or not decision.enforcement_required:
                return EnforcementResult(
                    success=True,
                    rule_id="no-rule",
                    target_ip=decision.target_ip,
                    target_port=decision.target_port,
                    action=decision.policy_action,
                    status="SKIPPED",
                    mode=self.mode_name,
                    message=f"[SANDBOX] Action '{decision.policy_action}' does not install a blocking rule.",
                    ttl_seconds=0,
                    expires_at=now,
                )

            effective_port = None if decision.policy_action == "Block" else decision.target_port
            effective_proto = "ANY" if decision.policy_action == "Block" else (decision.protocol or "TCP")
            expires_at = now + timedelta(seconds=decision.suggested_ttl_seconds)

            rule = ActiveEnforcementRule(
                rule_id=rule_id,
                event_id=decision.event_id,
                target_ip=decision.target_ip,
                target_port=effective_port,
                protocol=effective_proto,
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

            lab_synced, lab_sync_msg = self._sync_to_lab_router(
                operation="ADD",
                rule_id=rule_id,
                target_ip=decision.target_ip,
                action=decision.policy_action,
                target_port=effective_port,
                protocol=effective_proto,
                ttl_seconds=decision.suggested_ttl_seconds,
            )

            if decision.policy_action == "Block":
                msg = f"[SANDBOX] Host {decision.target_ip} quarantined. All subsequent traffic dropped."
            elif decision.policy_action == "Restrict":
                msg = f"[SANDBOX] Restriction applied to {decision.target_ip} on port {effective_port}."
            else:
                msg = f"[SANDBOX] Observational rule applied for {decision.target_ip}."

            if lab_synced:
                msg = f"{msg} [LAB_ROUTER_IPTABLES_SYNCED]"

            return EnforcementResult(
                success=True,
                rule_id=rule_id,
                target_ip=decision.target_ip,
                target_port=effective_port,
                action=decision.policy_action,
                status="ACTIVE",
                mode=self.mode_name,
                message=msg,
                ttl_seconds=decision.suggested_ttl_seconds,
                expires_at=expires_at,
                metadata={
                    "sandbox": True,
                    "active_rules_count": len(self._rules),
                    "lab_enforcement_enabled": getattr(settings, "lab_enforcement_enabled", False),
                    "lab_router_synced": lab_synced,
                    "lab_router_note": lab_sync_msg,
                },
            )

    def revoke(
        self,
        rule_id: str,
        actor: str = "analyst",
        target_ip: Optional[str] = None,
        action: Optional[str] = None,
        target_port: Optional[int] = None,
        protocol: Optional[str] = None,
    ) -> EnforcementResult:
        with self._lock:
            rule = self._rules.get(rule_id)
            if not rule:
                if target_ip and action:
                    now = datetime.now(timezone.utc)
                    lab_synced, lab_sync_msg = self._sync_to_lab_router(
                        operation="REMOVE",
                        rule_id=rule_id,
                        target_ip=target_ip,
                        action=action,
                        target_port=target_port,
                        protocol=protocol or "TCP",
                        ttl_seconds=0,
                    )
                    return EnforcementResult(
                        success=True,
                        rule_id=rule_id,
                        target_ip=target_ip,
                        target_port=target_port,
                        action=action,  # type: ignore
                        status="REVOKED",
                        mode=self.mode_name,
                        message=f"[SANDBOX] Containment rule '{rule_id}' for {target_ip} revoked.",
                        ttl_seconds=0,
                        expires_at=now,
                        metadata={
                            "revoked_by": actor,
                            "lab_router_synced": lab_synced,
                            "lab_router_note": lab_sync_msg,
                        },
                    )
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

            lab_synced, lab_sync_msg = self._sync_to_lab_router(
                operation="REMOVE",
                rule_id=rule_id,
                target_ip=rule.target_ip,
                action=rule.action,
                target_port=rule.target_port,
                protocol=rule.protocol or "TCP",
                ttl_seconds=0,
            )

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
                metadata={
                    "revoked_by": actor,
                    "lab_router_synced": lab_synced,
                    "lab_router_note": lab_sync_msg,
                },
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
            expired_rules: List[ActiveEnforcementRule] = []
            for rule_id, rule in list(self._rules.items()):
                if rule.status == "ACTIVE" and rule.expires_at <= now:
                    rule.status = "EXPIRED"
                    expired_ids.append(rule_id)
                    expired_rules.append(rule)

            if expired_ids:
                self._rebuild_lookup_tables()
                for exp_rule in expired_rules:
                    spec_tuple = self._canonical_spec(
                        exp_rule.target_ip, exp_rule.action, exp_rule.target_port
                    )
                    if not self._is_spec_referenced(spec_tuple, now=now):
                        self._sync_to_lab_router(
                            operation="REMOVE",
                            rule_id=exp_rule.rule_id,
                            target_ip=exp_rule.target_ip,
                            action=exp_rule.action,
                            target_port=exp_rule.target_port,
                            protocol=exp_rule.protocol or "TCP",
                            ttl_seconds=0,
                        )

            return expired_ids

    def ensure_router_convergence(self) -> int:
        """
        Ensures lab-router's active_containment_rules and HYBRID_LAB_CONTAINMENT chain
        converge with SandboxAdapter's currently active, non-expired rules when LAB_ENFORCEMENT_ENABLED=true.
        """
        if not getattr(settings, "lab_enforcement_enabled", False):
            return 0
        with self._lock:
            active_rules = self.list_active_rules()
            active_rule_ids = {r.rule_id for r in active_rules}
            router_url = getattr(settings, "lab_router_url", "http://10.30.10.2:8099").rstrip("/")
            if "localhost" in router_url.lower() or "127.0.0.1" in router_url or "::1" in router_url:
                return 0
            try:
                with urllib.request.urlopen(f"{router_url}/api/status", timeout=1.5) as resp:
                    status_data = json.loads(resp.read().decode("utf-8"))
                router_rules = list(status_data.get("active_containment_rules", []))
                router_rule_ids = {str(r.get("rule_id")) for r in router_rules}
                containment_counters = str(status_data.get("containment_chain_counters", ""))
            except Exception:
                return 0

            resynced = 0
            # 1. Remove any stale rules on lab-router that are no longer active
            for r_info in router_rules:
                rid = str(r_info.get("rule_id", ""))
                if rid and rid not in active_rule_ids:
                    ok, _ = self._sync_to_lab_router(
                        operation="REMOVE",
                        rule_id=rid,
                        target_ip=str(r_info.get("target_ip", "")),
                        action=str(r_info.get("action", "Block")),
                        target_port=r_info.get("target_port"),
                        protocol="TCP",
                        ttl_seconds=0,
                    )
                    if ok:
                        resynced += 1

            # 2. Add any active rules missing from lab-router
            now = datetime.now(timezone.utc)
            for rule in active_rules:
                if not self._is_valid_lab_target(rule.target_ip):
                    continue
                rem_ttl = max(int((rule.expires_at - now).total_seconds()), 0)
                if rem_ttl <= 0:
                    continue
                needs_sync = (
                    rule.rule_id not in router_rule_ids
                    or rule.target_ip not in containment_counters
                )
                if needs_sync:
                    ok, _ = self._sync_to_lab_router(
                        operation="ADD",
                        rule_id=rule.rule_id,
                        target_ip=rule.target_ip,
                        action=rule.action,
                        target_port=rule.target_port,
                        protocol=rule.protocol or "ANY",
                        ttl_seconds=rem_ttl,
                    )
                    if ok:
                        resynced += 1
            return resynced

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
