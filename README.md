# AICM - Agent Integrity & Compromise Monitor

A security monitoring system designed to detect and quarantine compromised AI agents, with specific focus on detecting participation in "skill-sharing" networks like Moltbook that can dynamically change an agent's code supply chain.

```
     ┌──────────────────────────────────────────────────────────────────┐
     │                        AICM Architecture                         │
     └──────────────────────────────────────────────────────────────────┘
     
     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
     │  Agent #1   │     │  Agent #2   │     │  Agent #N   │
     │ ┌─────────┐ │     │ ┌─────────┐ │     │ ┌─────────┐ │
     │ │ Sensor  │ │     │ │ Sensor  │ │     │ │ Sensor  │ │
     │ └────┬────┘ │     │ └────┬────┘ │     │ └────┬────┘ │
     └──────┼──────┘     └──────┼──────┘     └──────┼──────┘
            │                   │                   │
            └───────────────────┼───────────────────┘
                                │ HTTPS/mTLS
                                ▼
            ┌───────────────────────────────────────┐
            │            AICM Server                │
            │  ┌─────────────────────────────────┐  │
            │  │        FastAPI Backend          │  │
            │  │  ┌──────────┐  ┌─────────────┐  │  │
            │  │  │ Policy   │  │  Telemetry  │  │  │
            │  │  │ Engine   │  │  Ingestion  │  │  │
            │  │  └──────────┘  └─────────────┘  │  │
            │  │  ┌──────────────────────────┐   │  │
            │  │  │      SQLite/Postgres     │   │  │
            │  │  └──────────────────────────┘   │  │
            │  └─────────────────────────────────┘  │
            └───────────────────────────────────────┘
                                │
                                ▼
            ┌───────────────────────────────────────┐
            │          React Dashboard              │
            │  ┌─────────┐ ┌─────────┐ ┌─────────┐  │
            │  │ Agents  │ │Incidents│ │Policies │  │
            │  └─────────┘ └─────────┘ └─────────┘  │
            └───────────────────────────────────────┘
```

## Core Design Principle

**Never let "joining Moltbook" be a runtime capability.**

Treat it as a policy violation that triggers immediate quarantine. When an agent joins a skill-sharing network, your trust boundary shifts from "you control the agent" to "the network can influence the agent."

## What It Detects

### High Severity Signals
- New skill installed without valid signature
- Skill directory changed + outbound requests to unknown domains  
- Agent accessed secrets after reading untrusted content

### Medium Severity Signals
- Moltbook endpoints contacted
- Large egress data spike
- New persistence mechanisms (cron, startup items)

### Low Severity Signals
- New domain contacted without tool escalation
- Minor config changes

## Components

### 1. Agent Sensor (`sensor/agent_sensor.py`)

Lightweight Python daemon that runs on each agent host and monitors:

- **File Integrity**: SHA256 hashes of skills/plugins directories
- **Network Egress**: Connections, domains, unusual traffic
- **Moltbook Detection**: Config files, environment variables, domain contacts
- **Secret Access**: Reads to .env, .aws/credentials, etc.

```bash
# Run once (for testing)
python sensor/agent_sensor.py --once

# Run as daemon
python sensor/agent_sensor.py --server http://aicm-server:8000
```

### 2. Server (`server/main.py`)

FastAPI backend that:

- Ingests telemetry from sensors
- Runs policy engine to assess risk
- Issues quarantine commands
- Stores events in SQLite/Postgres
- Serves dashboard API

```bash
# Development
uvicorn server.main:app --reload

# Production
gunicorn server.main:app -w 4 -k uvicorn.workers.UvicornWorker
```

### 3. Dashboard (`dashboard/Dashboard.jsx`)

React UI showing:

- Agent inventory with status indicators
- Real-time risk scores
- Incident timeline
- Quarantine/release controls
- Policy management

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the Server

```bash
cd server
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 3. Deploy Sensors

On each agent host:

```bash
python sensor/agent_sensor.py \
  --server http://your-aicm-server:8000 \
  --interval 60
```

### 4. View Dashboard

The React dashboard can be run standalone or integrated into your existing frontend:

```bash
# Using Vite/CRA
npm create vite@latest aicm-dashboard -- --template react
cp dashboard/Dashboard.jsx aicm-dashboard/src/
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/telemetry` | POST | Receive telemetry from sensors |
| `/api/v1/agents` | GET | List all agents |
| `/api/v1/agents/{id}` | GET | Get agent details |
| `/api/v1/agents/{id}/quarantine` | POST | Quarantine an agent |
| `/api/v1/agents/{id}/release` | POST | Release from quarantine |
| `/api/v1/incidents` | GET | List incidents |
| `/api/v1/incidents/{id}/resolve` | POST | Resolve incident |
| `/api/v1/dashboard/stats` | GET | Dashboard statistics |
| `/api/v1/approved-hashes` | GET/POST | Manage hash allowlist |

## Policy Rules

Default policies (can be customized in DB):

1. **Moltbook Quarantine**: Auto-quarantine any agent that joins Moltbook
2. **High Risk Threshold**: Quarantine agents with risk score > 70
3. **Unsigned Skill Alert**: Alert on unsigned skill installation

## Securing Your Specific Agents

### RewmoAI (Finance Context)

```python
# Treat any autonomous skill install as stop-the-world
SensorConfig(
    watch_directories=[
        "~/.rewmo/skills",
        "~/.rewmo/tools",
    ],
    # Strict: block any network except your API
    allowed_egress_domains=[
        "api.rewmoai.com",
        "api.openai.com",  # or your LLM provider
    ]
)
```

### ProjMgtAI (Construction Docs)

```python
# Focus on data exfil + credential theft
SensorConfig(
    sensitive_paths=[
        "~/project-docs/",
        "~/.config/projmgt/",
        ".env",
    ],
    # Lock down filesystem + network egress
    watch_directories=[
        "~/project-docs/",
        "~/.projmgt/skills",
    ]
)
```

## Production Considerations

1. **Use mTLS** for sensor-server communication
2. **Sign your skills** with your own key; reject unsigned
3. **Store telemetry in Postgres** for production volumes
4. **Export to SIEM** (Splunk, Elastic) for correlation
5. **Add alerting** (PagerDuty, Slack webhooks)

## Extending

### Add Custom Indicators

```python
# In agent_sensor.py
class CustomDetector:
    def detect_suspicious_tool_usage(self) -> list[MoltbookIndicator]:
        # Your custom detection logic
        pass
```

### Add Policy Rules

```python
# In server/main.py
PolicyRule(
    name="custom_rule",
    condition_type="egress_spike",
    condition_params={'threshold_mb': 100},
    action="alert",
    severity="medium"
)
```

## License

MIT

## Contributing

PRs welcome! Focus areas:

- Additional platform support (Windows, containers)
- More sophisticated behavioral analysis
- Integration with common agent frameworks (LangChain, etc.)
