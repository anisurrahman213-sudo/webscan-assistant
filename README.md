# Red-Team Assistant

A **human-in-control** assistant for authorized security assessments. The
assistant reasons, correlates findings and writes reports, but **every active
action against a target requires explicit human approval** -- it never attacks
autonomously.

> Use only against systems you are explicitly authorized to test. The Rules of
> Engagement file (`engagement.yaml`) defines the authorized scope; anything
> outside it is denied.

## Components

**Phase 0 -- Foundation**

| File             | Purpose |
|------------------|---------|
| `finding.py`     | Normalized finding model shared by every component. |
| `scope.py`       | Loads Rules of Engagement from YAML; fail-closed scope checks (wildcard domains, CIDR IPs, risk ceiling, time window). |
| `audit.py`       | Append-only, hash-chained audit log with `verify()` tamper detection. |
| `approval.py`    | The Human Approval Gate: scope-check first, then ask the operator; fail-closed. |

**Phase 1 -- Tool interface**

| File             | Purpose |
|------------------|---------|
| `tool.py`        | Uniform `Tool` interface + `ToolResult`. |
| `registry.py`    | Catalog of available tools. |
| `runner.py`      | Runs a tool only after the Approval Gate allows it. |
| `tools/`         | Recon tools: HTTP security headers, tech detect, nmap port scan. |
| `tools/adapters.py` | `SubprocessTool` / `PythonFnTool` -- wrap any CLI or your own modules as Tools (see its docstring for the template). |

**Phase 2-4 -- Brain, correlation, reporting**

| File             | Purpose |
|------------------|---------|
| `llm.py`         | Multi-provider LLM client (anthropic/openai/ollama + offline mock). |
| `brain.py`       | Advisor brain: explain, triage, and suggest the next tool from the catalog. Advisory only -- no exploit code, no execution. |
| `correlation.py` | Rule-based attack-path view over the findings. |
| `report.py`      | Single-file HTML report. |
| `run.py`         | CLI tying it together (`--yes`, `--advise`, `--report`). |

Demos: `demo_phase0.py`, `demo_phase1.py`, `demo_phase234.py`.

### Core safety rules
- **Fail-closed** -- not in scope means denied.
- **Out-of-scope first** -- such proposals are blocked without asking the human.
- **No answer means no** -- a non-interactive session rejects, never approves.

## Install & run

```bash
pip install -r requirements.txt

# verify the framework offline
python3 demo_phase0.py
python3 demo_phase1.py
python3 demo_phase234.py

# run against an in-scope target
python3 run.py --target http://testphp.vulnweb.com --yes --report
```

## LLM configuration (for --advise)

Set one provider's key; priority is anthropic -> openai -> ollama. With none
set, an offline mock is used so nothing breaks.

```bash
export ANTHROPIC_API_KEY=...   # optional ANTHROPIC_MODEL=...
# or OPENAI_API_KEY / OPENAI_MODEL, or OLLAMA_HOST / OLLAMA_MODEL
```

## Wrapping your own modules
Use `PythonFnTool` (native Python) or `SubprocessTool` (external CLI) from
`tools/adapters.py`; the docstring there has a copy-paste template. Set the risk
level honestly -- anything `intrusive` or above always asks for approval.
Register the new tool in `run.py`'s `build_registry()`.
