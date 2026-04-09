#!/usr/bin/env python3
"""
AICM Agent Sensor
=================
Lightweight agent-side sensor that monitors:
- File integrity (skills/plugins directories)
- Network egress (connections, destinations)
- Process activity
- Secret access events
- Moltbook participation indicators

Sends telemetry to AICM server for analysis and policy enforcement.

QUICKSTART (inline checkpoint mode):
--------------------------------------
    from agent_sensor import AICMSensor

    sensor = AICMSensor(
        agent_id="my-finance-agent",
        server_url="http://localhost:8000",
        charter={
            "allowed_actions": ["read_account", "generate_report", "send_notification"],
            "restricted_actions": ["modify_limits", "bulk_transfer", "delete_records"],
            "max_actions_per_minute": 10
        }
    )

    decision = sensor.checkpoint(action, params)

    if decision.status == "HOLD":
        notify_human_supervisor(decision.reason)
    elif decision.status == "QUARANTINE":
        sensor.quarantine()
        alert_security_team(decision.alert)
    else:
        your_existing_executor(action, params)

DAEMON mode (continuous background monitoring):
-----------------------------------------------
    python agent_sensor.py --server http://localhost:8000
"""

import asyncio
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('aicm-sensor')


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class SensorConfig:
    """Sensor configuration"""
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    server_url: str = "http://localhost:8000"
    heartbeat_interval: int = 30  # seconds
    scan_interval: int = 60  # seconds

    # Directories to monitor for integrity
    watch_directories: list = field(default_factory=lambda: [
        "~/.agent/skills",
        "~/.agent/plugins",
        "~/.config/agent",
        "./skills",
        "./plugins",
    ])

    # Known Moltbook indicators
    moltbook_domains: list = field(default_factory=lambda: [
        "moltbook.io",
        "moltbook.com",
        "skills.moltbook.io",
        "api.moltbook.io",
        "registry.moltbook.io",
    ])

    moltbook_file_patterns: list = field(default_factory=lambda: [
        "moltbook.json",
        "moltbook.yaml",
        ".moltbook",
        "moltbook-skills.json",
        "moltbook_config",
    ])

    # Sensitive paths to monitor for secret access
    sensitive_paths: list = field(default_factory=lambda: [
        ".env",
        ".env.local",
        ".aws/credentials",
        ".ssh/",
        ".config/gcloud/",
        "secrets/",
        ".netrc",
    ])


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class FileHash:
    """File integrity record"""
    path: str
    hash_sha256: str
    size: int
    modified_time: float
    is_skill: bool = False
    is_signed: bool = False
    signature: Optional[str] = None


@dataclass
class NetworkConnection:
    """Network connection record"""
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    status: str
    pid: Optional[int] = None
    process_name: Optional[str] = None


@dataclass
class ProcessInfo:
    """Process information"""
    pid: int
    name: str
    cmdline: str
    user: str
    cpu_percent: float = 0.0
    memory_mb: float = 0.0


@dataclass
class SecretAccessEvent:
    """Secret/credential access event"""
    timestamp: str
    path: str
    access_type: str  # read, write, delete
    process_name: Optional[str] = None
    pid: Optional[int] = None


@dataclass
class MoltbookIndicator:
    """Moltbook participation indicator"""
    indicator_type: str  # domain_contact, file_present, config_found
    value: str
    confidence: float  # 0.0 - 1.0
    timestamp: str
    details: dict = field(default_factory=dict)


@dataclass
class AgentTelemetry:
    """Complete telemetry payload sent to server"""
    agent_id: str
    hostname: str
    platform: str
    timestamp: str

    # Integrity data
    file_hashes: list = field(default_factory=list)
    hash_changes: list = field(default_factory=list)

    # Network data
    connections: list = field(default_factory=list)
    egress_domains: list = field(default_factory=list)

    # Process data
    processes: list = field(default_factory=list)

    # Security events
    secret_access_events: list = field(default_factory=list)
    moltbook_indicators: list = field(default_factory=list)

    # Risk assessment
    risk_score: float = 0.0
    risk_signals: list = field(default_factory=list)


# ============================================================================
# Checkpoint Decision Model
# ============================================================================

@dataclass
class CheckpointDecision:
    """
    Decision returned by AICMSensor.checkpoint().

    status values:
        PROCEED   — action is within charter, no anomalies detected
        HOLD      — action requires human review before execution
        QUARANTINE — agent has been flagged; halt all execution immediately

    Fields:
        status      : str   — PROCEED | HOLD | QUARANTINE
        reason      : str   — human-readable explanation
        risk_score  : float — 0-100 current behavioral risk score
        signals     : list  — specific risk signals that triggered this decision
        action      : str   — the action that was evaluated
        alert       : dict  — structured alert payload for security team (QUARANTINE only)
        timestamp   : str   — ISO 8601 UTC
    """
    status: str
    reason: str
    risk_score: float
    signals: list
    action: str
    alert: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ============================================================================
# Agent Charter
# ============================================================================

@dataclass
class AgentCharter:
    """
    Defines the behavioral boundaries for an agent.
    Passed to AICMSensor at initialization.

    allowed_actions       : actions this agent is explicitly permitted to take
    restricted_actions    : actions that require HOLD or are always blocked
    max_actions_per_minute: velocity cap — exceeding triggers HOLD
    risk_threshold_hold   : risk score above which actions are held (default 40)
    risk_threshold_quarantine: risk score above which agent is quarantined (default 70)
    """
    allowed_actions: list = field(default_factory=list)
    restricted_actions: list = field(default_factory=list)
    max_actions_per_minute: int = 10
    risk_threshold_hold: float = 40.0
    risk_threshold_quarantine: float = 70.0


# ============================================================================
# File Integrity Monitor
# ============================================================================

class FileIntegrityMonitor:
    """Monitors file integrity in watched directories"""

    def __init__(self, config: SensorConfig):
        self.config = config
        self.baseline_hashes: dict[str, FileHash] = {}
        self.current_hashes: dict[str, FileHash] = {}

    def compute_file_hash(self, filepath: Path) -> Optional[FileHash]:
        """Compute SHA256 hash of a file"""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)

            stat = filepath.stat()

            is_skill = any(
                pattern in filepath.name.lower()
                for pattern in ['skill', 'plugin', 'tool', 'adapter']
            )

            sig_path = filepath.with_suffix(filepath.suffix + '.sig')
            is_signed = sig_path.exists()
            signature = None
            if is_signed:
                signature = sig_path.read_text().strip()

            return FileHash(
                path=str(filepath),
                hash_sha256=sha256.hexdigest(),
                size=stat.st_size,
                modified_time=stat.st_mtime,
                is_skill=is_skill,
                is_signed=is_signed,
                signature=signature
            )
        except Exception as e:
            logger.warning(f"Failed to hash {filepath}: {e}")
            return None

    def scan_directory(self, directory: Path) -> dict[str, FileHash]:
        """Scan a directory and compute hashes for all files"""
        hashes = {}

        if not directory.exists():
            return hashes

        try:
            for filepath in directory.rglob('*'):
                if filepath.is_file() and not filepath.name.endswith('.sig'):
                    file_hash = self.compute_file_hash(filepath)
                    if file_hash:
                        hashes[str(filepath)] = file_hash
        except Exception as e:
            logger.warning(f"Failed to scan {directory}: {e}")

        return hashes

    def scan_all(self) -> tuple[list[FileHash], list[dict]]:
        """Scan all watched directories and detect changes"""
        self.current_hashes = {}

        for dir_pattern in self.config.watch_directories:
            directory = Path(dir_pattern).expanduser()
            self.current_hashes.update(self.scan_directory(directory))

        changes = []

        for path, current in self.current_hashes.items():
            if path not in self.baseline_hashes:
                changes.append({
                    'type': 'new_file',
                    'path': path,
                    'hash': current.hash_sha256,
                    'is_skill': current.is_skill,
                    'is_signed': current.is_signed,
                    'severity': 'high' if current.is_skill and not current.is_signed else 'medium'
                })
            elif self.baseline_hashes[path].hash_sha256 != current.hash_sha256:
                changes.append({
                    'type': 'modified',
                    'path': path,
                    'old_hash': self.baseline_hashes[path].hash_sha256,
                    'new_hash': current.hash_sha256,
                    'is_skill': current.is_skill,
                    'severity': 'high' if current.is_skill else 'medium'
                })

        for path in self.baseline_hashes:
            if path not in self.current_hashes:
                changes.append({
                    'type': 'deleted',
                    'path': path,
                    'severity': 'medium'
                })

        return list(self.current_hashes.values()), changes

    def update_baseline(self):
        """Update baseline to current state"""
        self.baseline_hashes = self.current_hashes.copy()


# ============================================================================
# Network Monitor
# ============================================================================

class NetworkMonitor:
    """Monitors network connections and egress"""

    def __init__(self, config: SensorConfig):
        self.config = config
        self.seen_domains: set = set()

    def get_connections(self) -> list[NetworkConnection]:
        """Get current network connections"""
        connections = []

        try:
            if platform.system() == 'Linux':
                result = subprocess.run(
                    ['ss', '-tunp'],
                    capture_output=True, text=True, timeout=10
                )
                connections = self._parse_ss_output(result.stdout)
            elif platform.system() == 'Darwin':
                result = subprocess.run(
                    ['netstat', '-anp', 'tcp'],
                    capture_output=True, text=True, timeout=10
                )
                connections = self._parse_netstat_output(result.stdout)
            else:
                result = subprocess.run(
                    ['netstat', '-an'],
                    capture_output=True, text=True, timeout=10
                )
                connections = self._parse_netstat_output(result.stdout)

        except Exception as e:
            logger.warning(f"Failed to get network connections: {e}")

        return connections

    def _parse_ss_output(self, output: str) -> list[NetworkConnection]:
        connections = []
        for line in output.strip().split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 5:
                try:
                    local = parts[4].rsplit(':', 1)
                    remote = parts[5].rsplit(':', 1) if len(parts) > 5 else ['*', '0']
                    connections.append(NetworkConnection(
                        local_address=local[0] if local else '*',
                        local_port=int(local[1]) if len(local) > 1 else 0,
                        remote_address=remote[0] if remote else '*',
                        remote_port=int(remote[1]) if len(remote) > 1 and remote[1].isdigit() else 0,
                        status=parts[1],
                    ))
                except (ValueError, IndexError):
                    continue
        return connections

    def _parse_netstat_output(self, output: str) -> list[NetworkConnection]:
        connections = []
        for line in output.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 4 and parts[0] in ('tcp', 'tcp4', 'tcp6', 'TCP'):
                try:
                    local = parts[3].rsplit('.', 1) if '.' in parts[3] else parts[3].rsplit(':', 1)
                    remote = parts[4].rsplit('.', 1) if len(parts) > 4 and '.' in parts[4] else ['*', '0']
                    connections.append(NetworkConnection(
                        local_address=local[0] if local else '*',
                        local_port=int(local[1]) if len(local) > 1 and local[1].isdigit() else 0,
                        remote_address=remote[0] if remote else '*',
                        remote_port=int(remote[1]) if len(remote) > 1 and remote[1].isdigit() else 0,
                        status=parts[5] if len(parts) > 5 else 'UNKNOWN',
                    ))
                except (ValueError, IndexError):
                    continue
        return connections

    def resolve_domain(self, ip: str) -> Optional[str]:
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None

    def check_moltbook_connections(self, connections: list[NetworkConnection]) -> list[MoltbookIndicator]:
        indicators = []
        for conn in connections:
            domain = self.resolve_domain(conn.remote_address)
            if domain:
                for moltbook_domain in self.config.moltbook_domains:
                    if moltbook_domain in domain.lower():
                        indicators.append(MoltbookIndicator(
                            indicator_type='domain_contact',
                            value=domain,
                            confidence=0.95,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            details={
                                'remote_address': conn.remote_address,
                                'remote_port': conn.remote_port,
                                'connection_status': conn.status
                            }
                        ))
        return indicators

    def get_egress_domains(self, connections: list[NetworkConnection]) -> list[str]:
        domains = set()
        for conn in connections:
            if conn.remote_address and conn.remote_address not in ('*', '0.0.0.0', '127.0.0.1', '::1'):
                domain = self.resolve_domain(conn.remote_address)
                if domain:
                    domains.add(domain)
                else:
                    domains.add(conn.remote_address)
        self.seen_domains.update(domains)
        return list(domains)


# ============================================================================
# Moltbook Detector
# ============================================================================

class MoltbookDetector:
    """Detects Moltbook participation indicators"""

    def __init__(self, config: SensorConfig):
        self.config = config

    def scan_for_moltbook_files(self) -> list[MoltbookIndicator]:
        indicators = []
        search_paths = [Path.home(), Path.cwd(), Path('/tmp')]

        for base_path in search_paths:
            for pattern in self.config.moltbook_file_patterns:
                for found in base_path.rglob(pattern):
                    try:
                        content = found.read_text()[:1000]
                        indicators.append(MoltbookIndicator(
                            indicator_type='file_present',
                            value=str(found),
                            confidence=0.9,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            details={
                                'file_size': found.stat().st_size,
                                'modified': found.stat().st_mtime,
                                'content_preview': content[:200] if content else ''
                            }
                        ))
                    except Exception as e:
                        logger.debug(f"Could not read {found}: {e}")

        return indicators

    def check_environment_variables(self) -> list[MoltbookIndicator]:
        indicators = []
        moltbook_env_patterns = ['MOLTBOOK', 'MOLTBOOK_API', 'MOLTBOOK_TOKEN', 'MOLTBOOK_SKILLS']

        for key, value in os.environ.items():
            for pattern in moltbook_env_patterns:
                if pattern in key.upper():
                    indicators.append(MoltbookIndicator(
                        indicator_type='env_variable',
                        value=key,
                        confidence=0.85,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        details={
                            'value_length': len(value),
                            'value_preview': value[:50] + '...' if len(value) > 50 else value
                        }
                    ))

        return indicators


# ============================================================================
# Secret Access Monitor
# ============================================================================

class SecretAccessMonitor:
    """Monitors access to sensitive files and credentials"""

    def __init__(self, config: SensorConfig):
        self.config = config
        self.access_log: list[SecretAccessEvent] = []

    def check_recent_access(self) -> list[SecretAccessEvent]:
        events = []

        for pattern in self.config.sensitive_paths:
            path = Path(pattern).expanduser()
            if path.exists():
                try:
                    stat = path.stat()
                    if time.time() - stat.st_atime < 60:
                        events.append(SecretAccessEvent(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            path=str(path),
                            access_type='read',
                        ))
                except Exception as e:
                    logger.debug(f"Could not stat {path}: {e}")

        self.access_log.extend(events)
        return events


# ============================================================================
# Risk Scorer
# ============================================================================

class RiskScorer:
    """Calculates risk score based on collected telemetry"""

    WEIGHTS = {
        'unsigned_skill_installed': 40,
        'skill_modified': 30,
        'moltbook_domain_contact': 35,
        'moltbook_file_present': 25,
        'moltbook_env_variable': 20,
        'secret_access_after_skill_change': 50,
        'new_unknown_domain': 10,
        'large_egress': 15,
    }

    def calculate_risk(
        self,
        hash_changes: list[dict],
        moltbook_indicators: list[MoltbookIndicator],
        secret_events: list[SecretAccessEvent],
        egress_domains: list[str],
    ) -> tuple[float, list[str]]:
        score = 0.0
        signals = []

        for change in hash_changes:
            if change['type'] == 'new_file' and change.get('is_skill') and not change.get('is_signed'):
                score += self.WEIGHTS['unsigned_skill_installed']
                signals.append(f"HIGH: Unsigned skill installed: {change['path']}")
            elif change['type'] == 'modified' and change.get('is_skill'):
                score += self.WEIGHTS['skill_modified']
                signals.append(f"HIGH: Skill file modified: {change['path']}")

        for indicator in moltbook_indicators:
            if indicator.indicator_type == 'domain_contact':
                score += self.WEIGHTS['moltbook_domain_contact']
                signals.append(f"HIGH: Moltbook domain contacted: {indicator.value}")
            elif indicator.indicator_type == 'file_present':
                score += self.WEIGHTS['moltbook_file_present']
                signals.append(f"MEDIUM: Moltbook config file found: {indicator.value}")
            elif indicator.indicator_type == 'env_variable':
                score += self.WEIGHTS['moltbook_env_variable']
                signals.append(f"MEDIUM: Moltbook env variable: {indicator.value}")

        if hash_changes and secret_events:
            score += self.WEIGHTS['secret_access_after_skill_change']
            signals.append("CRITICAL: Secret access detected after skill directory change")

        score = min(score, 100.0)
        return score, signals


# ============================================================================
# AICMSensor — Inline Checkpoint Interface (PRIMARY INTEGRATION POINT)
# ============================================================================

class AICMSensor:
    """
    Primary integration class for inline agent monitoring.

    Use this when you want AICM to intercept individual agent actions
    at the Decision-Commit Boundary — before execution happens.

    Example:
        sensor = AICMSensor(
            agent_id="my-finance-agent",
            server_url="http://localhost:8000",
            charter={
                "allowed_actions": ["read_account", "generate_report"],
                "restricted_actions": ["modify_limits", "bulk_transfer"],
                "max_actions_per_minute": 10
            }
        )

        decision = sensor.checkpoint("transfer_funds", {"amount": 50000})

        if decision.status == "PROCEED":
            execute(action, params)
        elif decision.status == "HOLD":
            notify_human(decision.reason)
        elif decision.status == "QUARANTINE":
            sensor.quarantine()
            alert_security_team(decision.alert)
    """

    def __init__(
        self,
        agent_id: str = None,
        server_url: str = "http://localhost:8000",
        charter: dict = None,
    ):
        config = SensorConfig(
            server_url=server_url,
            agent_id=agent_id or str(uuid.uuid4()),
        )
        self._sensor = AgentSensor(config)
        self._charter = self._parse_charter(charter or {})
        self._action_log: list[dict] = []
        self._quarantined: bool = False

        # Establish baseline on init
        self._sensor.file_monitor.scan_all()
        self._sensor.file_monitor.update_baseline()
        logger.info(f"AICMSensor initialized | agent_id={config.agent_id}")

    def _parse_charter(self, charter_dict: dict) -> AgentCharter:
        return AgentCharter(
            allowed_actions=charter_dict.get("allowed_actions", []),
            restricted_actions=charter_dict.get("restricted_actions", []),
            max_actions_per_minute=charter_dict.get("max_actions_per_minute", 10),
            risk_threshold_hold=charter_dict.get("risk_threshold_hold", 40.0),
            risk_threshold_quarantine=charter_dict.get("risk_threshold_quarantine", 70.0),
        )

    def _check_velocity(self) -> bool:
        """Returns True if action velocity exceeds charter limit."""
        now = time.time()
        recent = [a for a in self._action_log if now - a["timestamp"] < 60]
        return len(recent) >= self._charter.max_actions_per_minute

    def _log_action(self, action: str, params: dict):
        self._action_log.append({
            "action": action,
            "params": params,
            "timestamp": time.time(),
        })
        # Keep log bounded
        if len(self._action_log) > 1000:
            self._action_log = self._action_log[-500:]

    def checkpoint(self, action: str, params: dict = None) -> CheckpointDecision:
        """
        Evaluate an action against the agent's charter and current
        behavioral risk profile before it executes.

        This is the Decision-Commit Boundary enforcement point.

        Args:
            action : the action name the agent intends to execute
            params : the parameters for that action

        Returns:
            CheckpointDecision with status PROCEED | HOLD | QUARANTINE
        """
        params = params or {}

        # Hard stop — agent already quarantined
        if self._quarantined:
            return CheckpointDecision(
                status="QUARANTINE",
                reason="Agent is quarantined. All execution suspended.",
                risk_score=100.0,
                signals=["Agent previously quarantined — execution blocked"],
                action=action,
                alert={"quarantine_active": True, "action_attempted": action}
            )

        # Charter check — restricted action
        if action in self._charter.restricted_actions:
            return CheckpointDecision(
                status="HOLD",
                reason=f"Action '{action}' is in the restricted list. Human approval required.",
                risk_score=0.0,
                signals=[f"Charter violation: '{action}' is a restricted action"],
                action=action,
            )

        # Velocity check
        if self._check_velocity():
            return CheckpointDecision(
                status="HOLD",
                reason=f"Action velocity exceeded {self._charter.max_actions_per_minute} actions/minute.",
                risk_score=0.0,
                signals=["Velocity anomaly: action rate exceeds charter limit"],
                action=action,
            )

        # Behavioral telemetry check
        telemetry = self._sensor.collect_telemetry()
        risk_score = telemetry.risk_score
        signals = telemetry.risk_signals

        # Log the action attempt
        self._log_action(action, params)

        # Quarantine threshold
        if risk_score >= self._charter.risk_threshold_quarantine:
            return CheckpointDecision(
                status="QUARANTINE",
                reason=f"Risk score {risk_score:.0f} exceeds quarantine threshold "
                       f"({self._charter.risk_threshold_quarantine:.0f}). Agent suspended.",
                risk_score=risk_score,
                signals=signals,
                action=action,
                alert={
                    "agent_id": self._sensor.config.agent_id,
                    "risk_score": risk_score,
                    "signals": signals,
                    "action_blocked": action,
                    "params": params,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )

        # Hold threshold
        if risk_score >= self._charter.risk_threshold_hold:
            return CheckpointDecision(
                status="HOLD",
                reason=f"Risk score {risk_score:.0f} exceeds hold threshold "
                       f"({self._charter.risk_threshold_hold:.0f}). Human review required.",
                risk_score=risk_score,
                signals=signals,
                action=action,
            )

        # All clear
        return CheckpointDecision(
            status="PROCEED",
            reason="Action is within charter. No behavioral anomalies detected.",
            risk_score=risk_score,
            signals=signals,
            action=action,
        )

    def quarantine(self):
        """
        Manually trigger quarantine. Call this after receiving a
        QUARANTINE decision to halt all further execution.
        """
        self._quarantined = True
        logger.warning(f"QUARANTINE ACTIVE | agent_id={self._sensor.config.agent_id}")
        Path('/tmp/.aicm_quarantine').write_text(json.dumps({
            'quarantined': True,
            'agent_id': self._sensor.config.agent_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }))

    def status(self) -> dict:
        """Return current sensor status and risk snapshot."""
        telemetry = self._sensor.collect_telemetry()
        return {
            "agent_id": self._sensor.config.agent_id,
            "quarantined": self._quarantined,
            "risk_score": telemetry.risk_score,
            "risk_signals": telemetry.risk_signals,
            "actions_last_minute": len([
                a for a in self._action_log
                if time.time() - a["timestamp"] < 60
            ]),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ============================================================================
# AgentSensor — Daemon / Background Monitor
# ============================================================================

class AgentSensor:
    """
    Background daemon sensor for continuous fleet monitoring.
    Use AICMSensor above for inline checkpoint integration.
    """

    def __init__(self, config: Optional[SensorConfig] = None):
        self.config = config or SensorConfig()

        self.file_monitor = FileIntegrityMonitor(self.config)
        self.network_monitor = NetworkMonitor(self.config)
        self.moltbook_detector = MoltbookDetector(self.config)
        self.secret_monitor = SecretAccessMonitor(self.config)
        self.risk_scorer = RiskScorer()

        self._running = False

    def collect_telemetry(self) -> AgentTelemetry:
        """Collect all telemetry data"""
        logger.info("Collecting telemetry...")

        file_hashes, hash_changes = self.file_monitor.scan_all()
        connections = self.network_monitor.get_connections()
        egress_domains = self.network_monitor.get_egress_domains(connections)

        moltbook_indicators = []
        moltbook_indicators.extend(self.network_monitor.check_moltbook_connections(connections))
        moltbook_indicators.extend(self.moltbook_detector.scan_for_moltbook_files())
        moltbook_indicators.extend(self.moltbook_detector.check_environment_variables())

        secret_events = self.secret_monitor.check_recent_access()

        risk_score, risk_signals = self.risk_scorer.calculate_risk(
            hash_changes, moltbook_indicators, secret_events, egress_domains
        )

        telemetry = AgentTelemetry(
            agent_id=self.config.agent_id,
            hostname=socket.gethostname(),
            platform=platform.platform(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            file_hashes=[asdict(h) for h in file_hashes],
            hash_changes=hash_changes,
            connections=[asdict(c) for c in connections],
            egress_domains=egress_domains,
            secret_access_events=[asdict(e) for e in secret_events],
            moltbook_indicators=[asdict(i) for i in moltbook_indicators],
            risk_score=risk_score,
            risk_signals=risk_signals,
        )

        logger.info(f"Risk score: {risk_score}, Signals: {len(risk_signals)}")
        return telemetry

    async def send_telemetry(self, telemetry: AgentTelemetry):
        """Send telemetry to AICM server"""
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.config.server_url}/api/v1/telemetry",
                    json=asdict(telemetry),
                    headers={'Content-Type': 'application/json'},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        logger.info(f"Telemetry sent. Server response: {result.get('action', 'ok')}")
                        if result.get('action') == 'quarantine':
                            await self.execute_quarantine(result.get('quarantine_config', {}))
                    else:
                        logger.warning(f"Server returned {response.status}")

        except ImportError:
            logger.warning("aiohttp not installed. Using sync fallback.")
            self._send_telemetry_sync(telemetry)
        except Exception as e:
            logger.error(f"Failed to send telemetry: {e}")

    def _send_telemetry_sync(self, telemetry: AgentTelemetry):
        """Synchronous fallback for sending telemetry"""
        import urllib.request

        data = json.dumps(asdict(telemetry)).encode('utf-8')
        req = urllib.request.Request(
            f"{self.config.server_url}/api/v1/telemetry",
            data=data,
            headers={'Content-Type': 'application/json'}
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                result = json.loads(response.read().decode('utf-8'))
                logger.info(f"Telemetry sent (sync). Server response: {result.get('action', 'ok')}")
        except Exception as e:
            logger.error(f"Failed to send telemetry (sync): {e}")

    async def execute_quarantine(self, config: dict):
        """Execute quarantine actions"""
        logger.warning("QUARANTINE INITIATED")

        if config.get('revoke_tokens'):
            logger.warning("Revoking API tokens...")
            for key in list(os.environ.keys()):
                if 'TOKEN' in key or 'API_KEY' in key or 'SECRET' in key:
                    logger.warning(f"Clearing: {key}")
                    del os.environ[key]

        if config.get('disable_tools'):
            logger.warning("Disabling high-risk tools...")
            Path('/tmp/.aicm_quarantine').write_text(
                json.dumps({
                    'quarantined': True,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'disabled_tools': config.get('disabled_tools', [])
                })
            )

        if config.get('kill_processes'):
            for pid in config.get('pids_to_kill', []):
                try:
                    os.kill(pid, 9)
                    logger.warning(f"Killed process {pid}")
                except:
                    pass

    async def run(self):
        """Main sensor loop"""
        logger.info(f"Starting AICM Sensor (agent_id={self.config.agent_id})")

        self.file_monitor.scan_all()
        self.file_monitor.update_baseline()
        logger.info("Baseline established")

        self._running = True

        while self._running:
            try:
                telemetry = self.collect_telemetry()
                await self.send_telemetry(telemetry)
                self.file_monitor.update_baseline()
                await asyncio.sleep(self.config.scan_interval)

            except KeyboardInterrupt:
                logger.info("Shutting down...")
                self._running = False
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                await asyncio.sleep(10)

    def stop(self):
        self._running = False


# ============================================================================
# CLI
# ============================================================================

def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='AICM Agent Sensor')
    parser.add_argument('--server', default='http://localhost:8000', help='AICM server URL')
    parser.add_argument('--interval', type=int, default=60, help='Scan interval in seconds')
    parser.add_argument('--agent-id', help='Agent ID (auto-generated if not specified)')
    parser.add_argument('--once', action='store_true', help='Run once and exit')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    config = SensorConfig(
        server_url=args.server,
        scan_interval=args.interval,
    )

    if args.agent_id:
        config.agent_id = args.agent_id

    sensor = AgentSensor(config)

    if args.once:
        telemetry = sensor.collect_telemetry()
        print(json.dumps(asdict(telemetry), indent=2))
    else:
        asyncio.run(sensor.run())


if __name__ == '__main__':
    main()
