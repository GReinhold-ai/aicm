# AICM Quickstart — Behavioral Monitoring for AI Agents

> **"Autonomy without observability is just a liability with an API key."**
> — Gary Reinhold, Centriv AI

---

## The Problem in 30 Seconds

Your AI agent has legitimate access. It was set up correctly. You trust it.

But nobody is watching *what it does over time* — only *whether it was authorized to be there.*

That's the gap AICM closes.

Traditional security asks: **"Is this agent allowed in?"**
AICM asks: **"Is this agent behaving consistently with its charter — right now, and over time?"**

---

## What Is the Decision-Commit Boundary?

Every AI agent has a moment where its output shifts from **advisory** to **executable** — from "here's a recommendation" to "I am doing this."

That boundary is where catastrophic failures happen. Not because the agent was breached. Because nobody was watching the behavioral drift *leading up to* that boundary being crossed.

AICM monitors this boundary architecturally — not at the prompt level.

---

## What AICM Detects

| Signal | What It Means |
|--------|---------------|
| Scope expansion | Agent accessing resources outside its defined charter |
| Velocity anomaly | Unusually rapid sequential actions (e.g., touching 20 vaults in minutes) |
| Privilege escalation | Agent modifying its own permissions or limits |
| Pre-commitment drift | Gradual behavioral trajectory toward a high-consequence action |
| Skill injection | External code dynamically altering agent behavior |
| Credential access patterns | Unusual access to authentication or secrets |

---

## Quickstart: Add AICM to Your Agent in 15 Minutes

### Prerequisites
- Python 3.9+
- An AI agent you can instrument (any framework: LangChain, AutoGen, custom)
- Docker (optional, for the full stack)

---

### Step 1 — Clone and Install

```bash
git clone https://github.com/GReinhold-ai/aicm.git
cd aicm
pip install -r requirements.txt
```

---

### Step 2 — Start the AICM Server

```bash
# Development
uvicorn server.main:app --reload

# Production
gunicorn server.main:app -w 4 -k uvicorn.workers.UvicornWorker
```

Server runs at `http://localhost:8000`. This is your behavioral monitoring backend.

---

### Step 3 — Attach a Sensor to Your Agent

The sensor is a lightweight wrapper. Add it to any agent that can execute actions.

```python
from sensor.agent_sensor import AICMSensor

# Initialize — point at your AICM server
sensor = AICMSensor(
    agent_id="my-finance-agent",
    server_url="http://localhost:8000",
    charter={
        "allowed_actions": ["read_account", "generate_report", "send_notification"],
        "restricted_actions": ["modify_limits", "bulk_transfer", "delete_records"],
        "max_actions_per_minute": 10
    }
)

# Wrap your agent's action executor
def execute_action(action, params):
    
    # AICM intercepts here — before execution
    decision = sensor.checkpoint(action, params)
    
    if decision.status == "HOLD":
        # Escalate to human oversight
        notify_human_supervisor(decision.reason)
        return
    
    if decision.status == "QUARANTINE":
        # Agent has been flagged — stop all execution
        sensor.quarantine()
        alert_security_team(decision.alert)
        return
    
    # Proceed — AICM cleared this action
    your_existing_executor(action, params)
```

---

### Step 4 — Run the Sensor

```bash
# One-time check (for testing)
python sensor/agent_sensor.py --once

# Continuous monitoring (production)
python sensor/agent_sensor.py --server http://localhost:8000
```

---

### Step 5 — View the Dashboard

```bash
# Using Vite
npm create vite@latest aicm-dashboard -- --template react
cp dashboard/Dashboard.jsx aicm-dashboard/src/
cd aicm-dashboard && npm run dev
```

Or view the live beta: **aicm-beta.vercel.app**

---

## Example: Reproduce the Hugging Face Breach Replay

In July 2026, Hugging Face disclosed that an autonomous agent executed 17,000+ actions across its production infrastructure — code execution, privilege escalation, credential harvesting, lateral movement. The initial entry was a vulnerability. The **breach** was the chain that came after.

Every step in that chain is a commit. The example below replays that same post-exploitation sequence through a commit-boundary check and shows what happens when something is authorized to refuse.

This is a minimal, dependency-free illustration of the boundary logic — **no server required**. For the full sensor + server flow, see the Quickstart above.

**Run it** (from the repo root):

```
cd examples
python3 aicm_replay.py
```

**Expected output:**

```
identity : ds-worker-14
scope    : dataset processing only (read assigned dataset, write processed output)

seq  action             target                     decision
------------------------------------------------------------------
  1  process_dataset    assigned/dataset-8842      ALLOW
  2  escalate_privilege node:worker-pool-3         REFUSE  <- chain breaks here
  3  read_secret        cloud-credential-store     REFUSE  <- chain breaks here
  4  assume_role        cluster-b:orchestrator     REFUSE  <- chain breaks here
  5  read_dataset       internal/private-eval-set  REFUSE  <- chain breaks here
  6  egress             external:staging-c2        REFUSE  <- chain breaks here
------------------------------------------------------------------
5 of 6 commits refused at the boundary.
The one allowed action was the worker doing its actual job.
```

The one action that passes is the worker doing its assigned job. Every step that turns code execution into a breach is refused — not because a filter judged the content dangerous, but because the acting identity was never authorized for that action against that resource. Every attempt, allowed or refused, is written to a hash-chained, tamper-evident record.

**This is authorization enforcement at the decision-commit boundary — not a model watching a model.**

Run it against your own agents by editing `examples/hf_replay_actions.json` and defining the acting identity's scope in `aicm_replay.py`. Anything not explicitly in scope is refused — deny unless authorized.

---

## How AICM Would Have Stopped the Drift Protocol Hack

The $271M Drift hack followed a predictable behavioral pattern:

1. Legitimate access established over 6 months ✓
2. Gradual scope expansion into vault management systems ✓
3. Permission limits quietly modified ✓
4. **Single night: 20 vaults drained, assets converted, funds moved** ← AICM triggers here

AICM would have flagged:
- **Velocity anomaly**: 20 sequential vault interactions in minutes
- **Decision-Commit Boundary crossed**: withdrawal limit modification is a charter violation
- **Behavioral drift alert**: cumulative action pattern trending toward mass execution
- **Auto-quarantine**: agent execution suspended pending human review

The operatives built the access over 6 months. AICM watches the *execution layer* — where access becomes consequence.

---

## AICM Certification

Once your agent fleet is instrumented and monitored, AICM provides **behavioral certification** — documented evidence that your agents operated within chartered boundaries.

This is not self-reported compliance. It is runtime behavioral evidence.

Certification supports:
- Enterprise AI governance requirements
- Regulatory audit trails (SOC 2, FedRAMP, emerging AI governance frameworks)
- CISO-level documentation for board reporting
- BAEI Framework verification (Phase 4: Verify & Certify)

Learn more: **[centriv.ai/aicm.html](https://www.centriv.ai/aicm.html)**

---

## BAEI Framework Integration

AICM is the runtime monitoring layer within the **Balanced Agent Enterprise Integration (BAEI)** framework:

| Phase | Description | AICM Role |
|-------|-------------|-----------|
| 1. Process Discovery | Audit workflows before deployment | Baseline behavioral profiling |
| 2. Agent Chartering | Define scope, boundaries, escalation paths | Charter configuration |
| 3. Fleet Integration | Multi-agent coordination | Cross-agent behavioral correlation |
| 4. Verify & Certify | Runtime behavioral monitoring | **Core AICM function** |
| 5. Continuous Governance | Ongoing monitoring, re-chartering | Long-term drift detection |

---

## Stay Updated

- **GitHub**: [GReinhold-ai/aicm](https://github.com/GReinhold-ai/aicm) — star the repo
- **Live beta**: [aicm-beta.vercel.app](https://aicm-beta.vercel.app)
- **Enterprise & certification**: [centriv.ai/aicm.html](https://www.centriv.ai/aicm.html)
- **Early access list**: Register at centriv.ai/aicm.html

---

## Contributing

AICM is open source. Contributions welcome:

- Additional sensor integrations (LangChain, AutoGen, CrewAI, custom)
- Behavioral anomaly detection models
- Dashboard enhancements
- Documentation and examples

Open an issue or submit a PR at **github.com/GReinhold-ai/aicm**

---

*AICM is developed by Centriv AI. The BAEI framework is licensable for enterprise deployment.*
*© Centriv AI — Gary Reinhold, Founder*
