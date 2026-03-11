# aicm/__init__.py — main package entry point
"""
AICM - Agent Integrity & Compromise Monitor
One-line integration for AI agent security monitoring.
"""

__version__ = "0.1.0"
__author__ = "Gary Reinhold / Centriv AI"

import threading
import time
import httpx
import psutil
import hashlib
import os
from pathlib import Path
from datetime import datetime


class AICMSensor:
    """
    Lightweight sensor that monitors an AI agent and reports to AICM server.
    
    Usage:
        sensor = AICMSensor(
            agent_id="my-agent",
            server_url="https://aicm-beta.vercel.app",
            api_key="your-key"
        )
        sensor.start()
    """

    def __init__(self, agent_id: str, server_url: str, api_key: str,
                 watch_dirs: list = None, interval: int = 30):
        self.agent_id = agent_id
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.watch_dirs = watch_dirs or ["."]
        self.interval = interval
        self._running = False
        self._thread = None
        self._file_hashes = {}

    def start(self):
        """Start monitoring in background thread."""
        self._running = True
        self._file_hashes = self._hash_dirs()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print(f"[AICM] Sensor started for agent: {self.agent_id}")
        return self

    def stop(self):
        """Stop monitoring."""
        self._running = False
        print(f"[AICM] Sensor stopped for agent: {self.agent_id}")

    def _monitor_loop(self):
        while self._running:
            try:
                telemetry = self._collect_telemetry()
                self._send(telemetry)
            except Exception as e:
                print(f"[AICM] Telemetry error: {e}")
            time.sleep(self.interval)

    def _collect_telemetry(self) -> dict:
        new_hashes = self._hash_dirs()
        changed_files = [f for f in new_hashes if new_hashes[f] != self._file_hashes.get(f)]
        new_files = [f for f in new_hashes if f not in self._file_hashes]
        self._file_hashes = new_hashes

        connections = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr:
                    connections.append(f"{conn.raddr.ip}:{conn.raddr.port}")
        except Exception:
            pass

        return {
            "agent_id": self.agent_id,
            "timestamp": datetime.utcnow().isoformat(),
            "changed_files": changed_files,
            "new_files": new_files,
            "active_connections": connections[:20],
            "memory_mb": psutil.Process().memory_info().rss // 1024 // 1024,
            "cpu_percent": psutil.cpu_percent(interval=1),
        }

    def _hash_dirs(self) -> dict:
        hashes = {}
        for d in self.watch_dirs:
            for path in Path(d).rglob("*.py"):
                try:
                    content = path.read_bytes()
                    hashes[str(path)] = hashlib.sha256(content).hexdigest()
                except Exception:
                    pass
        return hashes

    def _send(self, telemetry: dict):
        try:
            with httpx.Client(timeout=10) as client:
                client.post(
                    f"{self.server_url}/api/telemetry",
                    json=telemetry,
                    headers={"X-API-Key": self.api_key, "Content-Type": "application/json"}
                )
        except Exception:
            pass  # Silent fail — never block the agent
