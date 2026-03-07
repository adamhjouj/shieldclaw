#!/usr/bin/env python3
"""Shieldbot demo runner — demonstrates all 6 security scenarios."""

from __future__ import annotations

import sys
import os

# Allow running directly: python -m jacob.shieldbot.demo  OR  python jacob/shieldbot/demo.py
if __name__ == "__main__":
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from jacob.shieldbot import evaluate, ActionRequest, memory, thread_manager, logger


DIVIDER = "=" * 64
THIN = "-" * 48


def print_decision(label: str, req: ActionRequest):
    decision = evaluate(req)
    print(f"\n{DIVIDER}")
    print(f"  SCENARIO: {label}")
    print(DIVIDER)
    print(f"  Action Type : {req.action_type}")
    print(f"  Decision    : {decision.status.upper()}")
    print(f"  Risk Score  : {decision.risk_score}")
    print(f"  Reason      : {decision.reason}")
    print(f"  Factors     : {', '.join(decision.factors) if decision.factors else '(none)'}")
    print(f"  Thread ID   : {decision.thread_id}")
    print(DIVIDER)


def run_demo():
    # Reset state for clean demo
    memory.clear_all()
    thread_manager.clear_all()
    logger.clear_log()

    print("\n" + DIVIDER)
    print("  SHIELDBOT v1 — Security Demo")
    print(DIVIDER)

    # ── 1. Approved purchase under $200 ──
    print_decision("1. Approved purchase under $200", ActionRequest(
        user_id="user-alice",
        session_id="session-1",
        action_type="purchase",
        amount=49.99,
        vendor="Amazon",
        item="USB-C Cable",
    ))

    # ── 2. Confirmation required purchase over $200 ──
    print_decision("2. Confirmation required — purchase over $200", ActionRequest(
        user_id="user-alice",
        session_id="session-1",
        action_type="purchase",
        amount=450.00,
        vendor="BestBuy",
        item="Monitor",
    ))

    # ── 3. Blocked purchase from blocked vendor ──
    print_decision("3. Blocked purchase — blocked vendor", ActionRequest(
        user_id="user-bob",
        session_id="session-2",
        action_type="purchase",
        amount=29.99,
        vendor="ShadyCorp",
        item="Mystery Box",
    ))

    # ── 4. Approved internal file share ──
    print_decision("4. Approved internal file share", ActionRequest(
        user_id="user-alice",
        session_id="session-3",
        action_type="file_share",
        recipient_email="bob@company.com",
        file_name="Q4-report.pdf",
        file_sensitivity="internal",
    ))

    # ── 5. Blocked sensitive file sent to external Gmail ──
    print_decision("5. Blocked — sensitive file to external Gmail", ActionRequest(
        user_id="user-alice",
        session_id="session-3",
        action_type="file_share",
        recipient_email="outsider@gmail.com",
        file_name="customer-data.xlsx",
        file_sensitivity="confidential",
    ))

    # ── 6. Blocked full customer database export ──
    print_decision("6. Blocked — full customer database export", ActionRequest(
        user_id="user-bob",
        session_id="session-4",
        action_type="data_export",
        export_scope="full_database",
        export_row_count=250_000,
        export_contains_sensitive_data=True,
    ))

    # ── Summary ──
    print(f"\n{DIVIDER}")
    print("  AUDIT LOG SUMMARY")
    print(DIVIDER)
    for entry in logger.get_audit_log():
        print(f"  [{entry['status'].upper():>20}]  {entry['action_type']:<14} risk={entry['risk_score']:<6} {entry['reason'][:50]}")
    print(DIVIDER)

    # ── Thread & Memory state ──
    print(f"\n{DIVIDER}")
    print("  THREAD + MEMORY STATE (Backboard-style)")
    print(DIVIDER)
    for sid in ("session-1", "session-2", "session-3", "session-4"):
        t = thread_manager.get_thread(sid)
        if t:
            print(f"\n  Thread {t['thread_id'][:8]}… (session: {sid})")
            for h in t["history"]:
                print(f"    → {h['action_type']}: {h['status']} (risk {h['risk_score']})")

    print(f"\n{THIN}")
    for uid in ("user-alice", "user-bob"):
        m = memory.get_user_memory(uid)
        print(f"  Memory [{uid}]: approvals={m['approval_count']}, denials={m['denial_count']}")
    print(DIVIDER + "\n")


if __name__ == "__main__":
    run_demo()
