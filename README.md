# Red-Team Assistant

A **human-in-control** assistant for authorized security assessments. The
assistant reasons, correlates findings and writes reports, but **every active
action against a target requires explicit human approval** -- it never attacks
autonomously.

> Use only against systems you are explicitly authorized to test. The Rules of
> Engagement file (`engagement.yaml`) defines the authorized scope; anything
> outside it is denied.

## Phase 0 -- Foundation (this release)

| File             | Purpose |
|------------------|---------|
| `finding.py`     | Normalized finding model shared by every component. |
| `scope.py`       | Loads Rules of Engagement from YAML; fail-closed scope checks (wildcard domains, CIDR IPs, risk ceiling, time window). |
| `audit.py`       | Append-only, hash-chained audit log with `verify()` tamper detection. |
| `approval.py`    | The Human Approval Gate: scope-check first, then ask the operator; fail-closed. |
| `engagement.yaml`| Example Rules of Engagement. |
| `demo_phase0.py` | End-to-end smoke test of the above. |

### Core safety rules
- **Fail-closed** -- not in scope means denied.
- **Out-of-scope first** -- such proposals are blocked without asking the human.
- **No answer means no** -- a non-interactive session rejects, never approves.

## Install & run

```bash
pip install -r requirements.txt
python3 demo_phase0.py
```

## Roadmap
- **Phase 1** -- Tool interface: wrap existing modules as suggestable tools with output interpretation.
- **Phase 2** -- Advisor core: LLM reasoning that proposes next steps.
- **Phase 3** -- Correlation / attack-path view.
- **Phase 4** -- Reporting engine.
