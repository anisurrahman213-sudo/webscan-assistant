"""
demo_phase0.py -- End-to-end smoke test of the Phase 0 foundation.

Run it from inside this folder:

    cd redteam_assistant
    python3 demo_phase0.py

Answer the [y/N] prompt for the in-scope action. The out-of-scope action is
blocked automatically, without ever asking you.
"""
from finding import Finding, Severity, Confidence
from scope import Scope, RiskLevel
from approval import ApprovalGate, ProposedAction
from audit import AuditLog


def main() -> None:
    # 1) A normalized finding, as a module would emit one.
    f = Finding(
        title="Possible SQL injection in login form",
        severity=Severity.HIGH,
        target="http://testphp.vulnweb.com/login.php",
        category="sqli",
        affected_param="uname",
        confidence=Confidence.FIRM,
        evidence="error: You have an error in your SQL syntax ...",
        module="module_21_sqli",
        tags=["sqli", "auth"],
    )
    print("FINDING:", f.summary())
    print(f.to_json())

    # 2) Load scope + a fresh audit log, wire up the gate.
    scope = Scope.from_yaml("engagement.yaml")
    audit = AuditLog("audit.log.jsonl")
    gate = ApprovalGate(scope, audit)

    # 3a) In-scope proposal -> the human is asked.
    res = gate.request(ProposedAction(
        tool="module_21_sqli",
        target="http://testphp.vulnweb.com/login.php",
        risk=RiskLevel.INTRUSIVE,
        rationale="FIRM SQLi signal on 'uname'; confirm with a safe probe.",
        params={"param": "uname"},
    ))
    print(f"\n--> Decision: {res.decision.value} ({res.reason})")

    # 3b) Out-of-scope proposal -> blocked WITHOUT asking the human.
    res2 = gate.request(ProposedAction(
        tool="module_21_sqli",
        target="https://payments.acme.example/pay",
        risk=RiskLevel.INTRUSIVE,
        rationale="(brain mistakenly suggested an out-of-scope host)",
    ))
    print(f"--> Decision: {res2.decision.value} ({res2.reason})")

    # 4) Prove the audit trail is intact.
    print("\nAudit chain valid:", audit.verify())


if __name__ == "__main__":
    main()
