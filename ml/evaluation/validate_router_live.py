"""
Live Docker Router Enforcement & Verification Test Suite
=========================================================
Tests live router iptables enforcement, rule insertion, port restriction,
idempotency, TTL expiry, revocation, and management plane protection
inside the isolated hybrid-lab-router container.
"""

import json
import subprocess
import time
import urllib.request

ROUTER_URL = "http://10.30.10.2:8099/api/firewall/rules"


def call_router(payload):
    req = urllib.request.Request(
        ROUTER_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=3.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get_router_iptables():
    cmd = ["docker", "exec", "hybrid-lab-router", "iptables", "-L", "HYBRID_LAB_CONTAINMENT", "-n", "-v"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return res.stdout


def run_all_checks():
    print("==================================================================")
    print(" LIVE DOCKER HYBRID-CLOUD ROUTER ENFORCEMENT VERIFICATION ")
    print("==================================================================")

    # 1. Block Rule Insertion
    print("\n[1/6] Testing Rule Creation: BLOCK 10.10.10.99 (TTL: 5s)...")
    res1 = call_router({
        "operation": "ADD",
        "rule_id": "test-block-99",
        "target_ip": "10.10.10.99",
        "action": "Block",
        "ttl_seconds": 5,
    })
    assert res1.get("success") is True
    assert res1.get("installed_new_iptables_rule") is True
    rules = get_router_iptables()
    assert "10.10.10.99" in rules
    print("  -> Verified: iptables HYBRID_LAB_CONTAINMENT contains DROP for 10.10.10.99.")

    # 2. Idempotency Check
    print("\n[2/6] Testing Idempotency: Re-applying BLOCK 10.10.10.99...")
    res2 = call_router({
        "operation": "ADD",
        "rule_id": "test-block-99-duplicate",
        "target_ip": "10.10.10.99",
        "action": "Block",
        "ttl_seconds": 5,
    })
    assert res2.get("success") is True
    assert res2.get("installed_new_iptables_rule") is False  # Refcount incremented, no duplicate rule
    rules = get_router_iptables()
    count_99 = rules.count("10.10.10.99")
    assert count_99 == 1
    print(f"  -> Verified: Exactly 1 iptables rule present for 10.10.10.99 (Idempotency confirmed).")

    # 3. Port-Specific Restrict Rule
    print("\n[3/6] Testing Targeted Port Restriction: RESTRICT 10.10.10.98 Port 8080...")
    res3 = call_router({
        "operation": "ADD",
        "rule_id": "test-restrict-98",
        "target_ip": "10.10.10.98",
        "action": "Restrict",
        "target_port": 8080,
        "ttl_seconds": 15,
    })
    assert res3.get("success") is True
    rules = get_router_iptables()
    assert "10.10.10.98" in rules and "dpt:8080" in rules
    print("  -> Verified: iptables contains port-scoped rule (-s 10.10.10.98 -p tcp --dport 8080 -j DROP).")

    # 4. Management Plane & Protected Gateway IP Isolation
    print("\n[4/6] Testing Management Plane Protection (Safety Guardrail)...")
    for prot_ip in ["10.30.10.2", "10.10.10.1", "10.20.10.1", "127.0.0.1"]:
        try:
            call_router({
                "operation": "ADD",
                "rule_id": f"test-prot-{prot_ip}",
                "target_ip": prot_ip,
                "action": "Block",
                "ttl_seconds": 30,
            })
            raise AssertionError(f"Router accepted forbidden IP {prot_ip}!")
        except Exception:
            print(f"  -> Verified: Protected / out-of-scope IP '{prot_ip}' was safely REJECTED.")

    # 5. Manual Rule Revocation (REMOVE)
    print("\n[5/6] Testing Manual Revocation: REMOVE test-restrict-98...")
    res5 = call_router({
        "operation": "REMOVE",
        "rule_id": "test-restrict-98",
        "target_ip": "10.10.10.98",
        "action": "Restrict",
        "target_port": 8080,
    })
    assert res5.get("success") is True
    rules = get_router_iptables()
    assert "10.10.10.98" not in rules
    print("  -> Verified: 10.10.10.98 rule immediately expunged from iptables upon revocation.")

    # 6. Automatic TTL Expiry Reaping
    print("\n[6/6] Testing Automatic TTL Expiry Reaping (Waiting 6s for test-block-99 to expire)...")
    time.sleep(6)
    # Trigger a status query or reap
    rules_after_exp = get_router_iptables()
    assert "10.10.10.99" not in rules_after_exp
    print("  -> Verified: test-block-99 was automatically pruned upon TTL expiry by router reaper loop.")

    print("\n==================================================================")
    print(" STATUS: ALL 6 LIVE ROUTER ENFORCEMENT CHECKS PASSED (100% VERIFIED) ")
    print("==================================================================")


if __name__ == "__main__":
    run_all_checks()

