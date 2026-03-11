# AICM — Agent Integrity & Compromise Monitor

> Open-source security monitoring for AI agents. Detects skill-injection attacks, credential theft, and auto-quarantines compromised agents.

[![AICM Certified](https://img.shields.io/badge/AICM-Certified-C9A84C?style=flat&labelColor=0a0c10)](https://github.com/GReinhold-ai/aicm)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)

Built by [Centriv AI](https://centriv.ai) — domain-expert AI agents for regulated industries.

---

## What is AICM?

AICM is a lightweight security layer you deploy alongside your AI agents. It monitors agent behavior in real time, detects compromise indicators, and auto-quarantines threats before they escalate.

Against the McKinsey Lilli attack vector (autonomous agent SQL injection via unauthenticated endpoints), AICM would have:
- Flagged unauthenticated endpoint exposure at deploy time
- Detected autonomous probing patterns before escalation
- Caught JSON key concatenation before SQL execution
- Auto-quarantined the compromised agent in under 1 second

Traditional scanners (including OWASP ZAP) missed it. AICM monitors behavior, not signatures.

---

## Architecture

```
  [Your Agent]          [Your Agent]          [Your Agent]
  [ Sensor  ]          [ Sensor  ]          [ Sensor  ]
       |                    |                    |
       └────────────────────┼────────────────────┘
                            │ HTTPS/mTLS
                            ▼
                   [ AICM Server        ]
                   [ FastAPI + Policy   ]
                   [ Engine + SQLite    ]
                            │
                            ▼
                   [ React Dashboard    ]
                   [ Agents/Incidents/  ]
                   [ Policies           ]
```

---

## Quick Install

### Option 1 — One command (recommended)

```bash
pip install aicm-monitor
```

Then add to your agent:

```python
from aicm import AICMSensor

sensor = AICMSensor(
    agent_id="your-agent-name",
    server_url="https://your-aicm-server.com",  # or use hosted: https://aicm-beta.vercel.app
    api_key="your-api-key"
)
sensor.start()
```

### Option 2 — Self-hosted (full control)

**Step 1 — Clone the repo**
```bash
git clone https://github.com/GReinhold-ai/aicm.git
cd aicm
```

**Step 2 — Install dependencies**
```bash
pip install -r requirements.txt
```

**Step 3 — Start the AICM server**
```bash
python main.py
# Server runs on http://localhost:8000
```

**Step 4 — Deploy the sensor on each agent host**
```bash
python agent_sensor.py --agent-id "your-agent-name" --server "http://localhost:8000"
```

**Step 5 — Open the dashboard**
```
http://localhost:8000/dashboard
```

That's it. Your agents are now monitored.

---

## What AICM Detects

| Severity | Signal |
|----------|--------|
| 🔴 HIGH | New skill installed without valid signature |
| 🔴 HIGH | Skill directory changed + outbound requests to unknown domains |
| 🔴 HIGH | Agent accessed secrets after reading untrusted content |
| 🟡 MEDIUM | Unauthenticated endpoint exposure |
| 🟡 MEDIUM | Large egress data spike |
| 🟡 MEDIUM | New persistence mechanisms (cron, startup items) |
| 🟢 LOW | New domain contacted without tool escalation |
| 🟢 LOW | Minor config changes |

---

## AICM Certification Badge

Once your agent passes AICM monitoring, display the badge in your README:

```markdown
[![AICM Certified](https://img.shields.io/badge/AICM-Certified-C9A84C?style=flat&labelColor=0a0c10)](https://github.com/GReinhold-ai/aicm)
```

Renders as:

[![AICM Certified](https://img.shields.io/badge/AICM-Certified-C9A84C?style=flat&labelColor=0a0c10)](https://github.com/GReinhold-ai/aicm)

To list your agent in the [AgentCharter marketplace](https://centriv.ai/agentcharter.html), AICM certification is required.

---

## Apply to Your Own Agents

If you're building multiple agents under one platform (like Centriv AI), run one AICM server and connect all agents to it:

```python
# Agent 1 — ProjMgt.AI
sensor_1 = AICMSensor(agent_id="projmgtai", server_url="https://your-aicm-server.com", api_key="...")
sensor_1.start()

# Agent 2 — RewmoAI
sensor_2 = AICMSensor(agent_id="rewmoai", server_url="https://your-aicm-server.com", api_key="...")
sensor_2.start()

# Agent N — any agent
sensor_n = AICMSensor(agent_id="agent-name", server_url="https://your-aicm-server.com", api_key="...")
sensor_n.start()
```

All agents report to one dashboard. One policy engine. One audit trail.

---

## Hosted Version

Don't want to self-host? Use the AICM hosted monitor at:

**[aicm-beta.vercel.app](https://aicm-beta.vercel.app)**

- Free tier: up to 3 agents
- No server setup required
- Dashboard included
- Register your agent and get an API key in under 2 minutes

---

## Regulated Industries

AICM is built for environments where agent compromise is a liability, not just an inconvenience:

- **Fintech & Banking** — credential theft, data exfiltration
- **Construction & Federal** — USACE compliance, supply chain integrity
- **Energy & Climate** — operational technology protection
- **Defense & Logistics** — theater-level supply chain security
- **Aviation & Aerospace** — safety-critical system monitoring

---

## Contributing

AICM is MIT licensed and open to contributors. Open an issue or PR at [github.com/GReinhold-ai/aicm](https://github.com/GReinhold-ai/aicm).

---

## Built By

**Gary Reinhold** — Founder & CEO, Centriv AI  
40+ years: U.S. Marine Corps (Desert Storm), Naval Aviation, KBR ($5.4B), Gorgon LNG  
[centriv.ai](https://centriv.ai) · [LinkedIn](https://linkedin.com/in/garyreinhold)

---

*AICM is a Centriv AI open-source project. AgentCharter certification requires active AICM monitoring.*
