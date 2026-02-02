"""
AICM Server
===========
FastAPI backend for the Agent Integrity & Compromise Monitor.

Handles:
- Telemetry ingestion from agent sensors
- Policy engine for risk assessment
- Quarantine commands
- Dashboard API
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional
import json
import logging
import uuid

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, String, Float, Integer, DateTime, Boolean, JSON, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session

# ============================================================================
# Logging
# ============================================================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('aicm-server')

# ============================================================================
# Database Setup
# ============================================================================

DATABASE_URL = "sqlite:///./aicm.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ============================================================================
# Database Models
# ============================================================================

class AgentStatus(str, Enum):
    HEALTHY = "healthy"
    WARNING = "warning"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"
    OFFLINE = "offline"


class Agent(Base):
    """Registered agent"""
    __tablename__ = "agents"
    
    id = Column(String, primary_key=True)
    hostname = Column(String, nullable=False)
    platform = Column(String)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    status = Column(String, default=AgentStatus.HEALTHY)
    risk_score = Column(Float, default=0.0)
    moltbook_joined = Column(Boolean, default=False)
    quarantined = Column(Boolean, default=False)
    quarantine_reason = Column(Text)
    
    # Relationships
    telemetry_events = relationship("TelemetryEvent", back_populates="agent")
    incidents = relationship("Incident", back_populates="agent")
    approved_hashes = relationship("ApprovedHash", back_populates="agent")


class TelemetryEvent(Base):
    """Telemetry event from agent"""
    __tablename__ = "telemetry_events"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    timestamp = Column(DateTime, nullable=False)
    
    risk_score = Column(Float, default=0.0)
    risk_signals = Column(JSON, default=list)
    
    file_hashes = Column(JSON, default=list)
    hash_changes = Column(JSON, default=list)
    connections = Column(JSON, default=list)
    egress_domains = Column(JSON, default=list)
    secret_access_events = Column(JSON, default=list)
    moltbook_indicators = Column(JSON, default=list)
    
    agent = relationship("Agent", back_populates="telemetry_events")


class Incident(Base):
    """Security incident"""
    __tablename__ = "incidents"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime)
    
    severity = Column(String, nullable=False)  # low, medium, high, critical
    title = Column(String, nullable=False)
    description = Column(Text)
    signals = Column(JSON, default=list)
    
    status = Column(String, default="open")  # open, investigating, resolved, false_positive
    resolution = Column(Text)
    
    agent = relationship("Agent", back_populates="incidents")


class ApprovedHash(Base):
    """Approved file hash (allowlist)"""
    __tablename__ = "approved_hashes"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"))  # null = global
    
    file_path_pattern = Column(String, nullable=False)
    hash_sha256 = Column(String, nullable=False)
    description = Column(String)
    approved_by = Column(String)
    approved_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime)
    
    agent = relationship("Agent", back_populates="approved_hashes")


class PolicyRule(Base):
    """Policy rule for risk assessment"""
    __tablename__ = "policy_rules"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False, unique=True)
    description = Column(Text)
    enabled = Column(Boolean, default=True)
    
    # Rule conditions
    condition_type = Column(String, nullable=False)  # moltbook_joined, risk_threshold, skill_change, etc.
    condition_params = Column(JSON, default=dict)
    
    # Actions
    action = Column(String, nullable=False)  # alert, quarantine, disable_tools
    action_params = Column(JSON, default=dict)
    
    severity = Column(String, default="medium")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# Create tables
Base.metadata.create_all(bind=engine)


# ============================================================================
# Pydantic Models (API)
# ============================================================================

class FileHashModel(BaseModel):
    path: str
    hash_sha256: str
    size: int
    modified_time: float
    is_skill: bool = False
    is_signed: bool = False
    signature: Optional[str] = None


class HashChangeModel(BaseModel):
    type: str  # new_file, modified, deleted
    path: str
    hash: Optional[str] = None
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    is_skill: bool = False
    is_signed: bool = False
    severity: str = "medium"


class NetworkConnectionModel(BaseModel):
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    status: str
    pid: Optional[int] = None
    process_name: Optional[str] = None


class SecretAccessEventModel(BaseModel):
    timestamp: str
    path: str
    access_type: str
    process_name: Optional[str] = None
    pid: Optional[int] = None


class MoltbookIndicatorModel(BaseModel):
    indicator_type: str
    value: str
    confidence: float
    timestamp: str
    details: dict = Field(default_factory=dict)


class TelemetryPayload(BaseModel):
    """Incoming telemetry from agent sensor"""
    agent_id: str
    hostname: str
    platform: str
    timestamp: str
    
    file_hashes: list[FileHashModel] = Field(default_factory=list)
    hash_changes: list[HashChangeModel] = Field(default_factory=list)
    connections: list[NetworkConnectionModel] = Field(default_factory=list)
    egress_domains: list[str] = Field(default_factory=list)
    secret_access_events: list[SecretAccessEventModel] = Field(default_factory=list)
    moltbook_indicators: list[MoltbookIndicatorModel] = Field(default_factory=list)
    
    risk_score: float = 0.0
    risk_signals: list[str] = Field(default_factory=list)


class TelemetryResponse(BaseModel):
    """Response to telemetry submission"""
    status: str
    action: str = "ok"  # ok, quarantine, alert
    quarantine_config: Optional[dict] = None
    message: Optional[str] = None


class AgentResponse(BaseModel):
    id: str
    hostname: str
    platform: Optional[str]
    first_seen: datetime
    last_seen: datetime
    status: str
    risk_score: float
    moltbook_joined: bool
    quarantined: bool


class IncidentResponse(BaseModel):
    id: str
    agent_id: str
    created_at: datetime
    resolved_at: Optional[datetime]
    severity: str
    title: str
    description: Optional[str]
    signals: list
    status: str


class DashboardStats(BaseModel):
    total_agents: int
    healthy_agents: int
    warning_agents: int
    compromised_agents: int
    quarantined_agents: int
    moltbook_participants: int
    open_incidents: int
    avg_risk_score: float


# ============================================================================
# Policy Engine
# ============================================================================

class PolicyEngine:
    """Evaluates telemetry against policy rules"""
    
    # Default risk thresholds
    WARNING_THRESHOLD = 30.0
    QUARANTINE_THRESHOLD = 70.0
    
    def __init__(self, db: Session):
        self.db = db
        self._load_rules()
    
    def _load_rules(self):
        """Load policy rules from database"""
        self.rules = self.db.query(PolicyRule).filter(PolicyRule.enabled == True).all()
    
    def evaluate(self, agent: Agent, telemetry: TelemetryPayload) -> TelemetryResponse:
        """Evaluate telemetry against policies"""
        
        action = "ok"
        quarantine_config = None
        incidents_to_create = []
        
        # Check for Moltbook participation (highest priority)
        if telemetry.moltbook_indicators:
            agent.moltbook_joined = True
            
            # This is a policy violation - quarantine immediately
            action = "quarantine"
            quarantine_config = {
                'revoke_tokens': True,
                'disable_tools': True,
                'disabled_tools': ['shell', 'file_write', 'email_send', 'payments']
            }
            
            incidents_to_create.append({
                'severity': 'critical',
                'title': 'Moltbook Participation Detected',
                'description': f"Agent joined Moltbook skill-sharing network. {len(telemetry.moltbook_indicators)} indicators found.",
                'signals': [i.model_dump() for i in telemetry.moltbook_indicators]
            })
        
        # Check risk score thresholds
        elif telemetry.risk_score >= self.QUARANTINE_THRESHOLD:
            action = "quarantine"
            agent.status = AgentStatus.COMPROMISED
            quarantine_config = {
                'revoke_tokens': True,
                'disable_tools': True,
                'disabled_tools': ['shell', 'file_write']
            }
            
            incidents_to_create.append({
                'severity': 'high',
                'title': f'High Risk Score: {telemetry.risk_score:.1f}',
                'description': f"Agent risk score exceeded quarantine threshold ({self.QUARANTINE_THRESHOLD})",
                'signals': telemetry.risk_signals
            })
        
        elif telemetry.risk_score >= self.WARNING_THRESHOLD:
            agent.status = AgentStatus.WARNING
            
            incidents_to_create.append({
                'severity': 'medium',
                'title': f'Elevated Risk Score: {telemetry.risk_score:.1f}',
                'description': f"Agent risk score exceeded warning threshold ({self.WARNING_THRESHOLD})",
                'signals': telemetry.risk_signals
            })
        
        else:
            agent.status = AgentStatus.HEALTHY
        
        # Check for unsigned skills (always flag)
        unsigned_skills = [
            c for c in telemetry.hash_changes 
            if c.type == 'new_file' and c.is_skill and not c.is_signed
        ]
        
        if unsigned_skills:
            incidents_to_create.append({
                'severity': 'high',
                'title': f'{len(unsigned_skills)} Unsigned Skill(s) Installed',
                'description': "New skill files installed without valid signatures",
                'signals': [s.model_dump() for s in unsigned_skills]
            })
        
        # Create incidents
        for incident_data in incidents_to_create:
            incident = Incident(
                agent_id=agent.id,
                **incident_data
            )
            self.db.add(incident)
        
        # Apply quarantine if needed
        if action == "quarantine":
            agent.quarantined = True
            agent.quarantine_reason = incidents_to_create[0]['title'] if incidents_to_create else "Policy violation"
            agent.status = AgentStatus.QUARANTINED
        
        return TelemetryResponse(
            status="received",
            action=action,
            quarantine_config=quarantine_config,
            message=f"Risk score: {telemetry.risk_score:.1f}"
        )


# ============================================================================
# FastAPI App
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """App lifespan handler"""
    # Startup
    logger.info("AICM Server starting...")
    init_default_policies()
    yield
    # Shutdown
    logger.info("AICM Server shutting down...")


app = FastAPI(
    title="AICM - Agent Integrity & Compromise Monitor",
    description="Monitor and protect AI agents from compromise",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    """Database session dependency"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_default_policies():
    """Initialize default policy rules"""
    db = SessionLocal()
    
    default_rules = [
        PolicyRule(
            name="moltbook_quarantine",
            description="Quarantine agents that join Moltbook",
            condition_type="moltbook_joined",
            condition_params={},
            action="quarantine",
            action_params={'revoke_tokens': True, 'disable_tools': True},
            severity="critical"
        ),
        PolicyRule(
            name="high_risk_quarantine",
            description="Quarantine agents with risk score > 70",
            condition_type="risk_threshold",
            condition_params={'threshold': 70.0},
            action="quarantine",
            action_params={'revoke_tokens': True},
            severity="high"
        ),
        PolicyRule(
            name="unsigned_skill_alert",
            description="Alert on unsigned skill installation",
            condition_type="unsigned_skill",
            condition_params={},
            action="alert",
            action_params={},
            severity="high"
        ),
    ]
    
    for rule in default_rules:
        existing = db.query(PolicyRule).filter(PolicyRule.name == rule.name).first()
        if not existing:
            db.add(rule)
    
    db.commit()
    db.close()
    logger.info("Default policies initialized")


# ============================================================================
# API Endpoints
# ============================================================================

# --- Telemetry ---

@app.post("/api/v1/telemetry", response_model=TelemetryResponse)
async def receive_telemetry(payload: TelemetryPayload, background_tasks: BackgroundTasks):
    """Receive telemetry from agent sensor"""
    db = SessionLocal()
    
    try:
        # Get or create agent
        agent = db.query(Agent).filter(Agent.id == payload.agent_id).first()
        
        if not agent:
            agent = Agent(
                id=payload.agent_id,
                hostname=payload.hostname,
                platform=payload.platform
            )
            db.add(agent)
            logger.info(f"New agent registered: {payload.agent_id} ({payload.hostname})")
        
        # Update agent
        agent.last_seen = datetime.now(timezone.utc)
        agent.hostname = payload.hostname
        agent.platform = payload.platform
        agent.risk_score = payload.risk_score
        
        # Store telemetry event
        event = TelemetryEvent(
            agent_id=payload.agent_id,
            timestamp=datetime.fromisoformat(payload.timestamp.replace('Z', '+00:00')),
            risk_score=payload.risk_score,
            risk_signals=payload.risk_signals,
            file_hashes=[h.model_dump() for h in payload.file_hashes],
            hash_changes=[c.model_dump() for c in payload.hash_changes],
            connections=[c.model_dump() for c in payload.connections],
            egress_domains=payload.egress_domains,
            secret_access_events=[e.model_dump() for e in payload.secret_access_events],
            moltbook_indicators=[i.model_dump() for i in payload.moltbook_indicators]
        )
        db.add(event)
        
        # Run policy engine
        policy_engine = PolicyEngine(db)
        response = policy_engine.evaluate(agent, payload)
        
        db.commit()
        
        logger.info(f"Telemetry received from {payload.agent_id}: risk={payload.risk_score:.1f}, action={response.action}")
        
        return response
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error processing telemetry: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


# --- Agents ---

@app.get("/api/v1/agents", response_model=list[AgentResponse])
async def list_agents(
    status: Optional[str] = None,
    moltbook_only: bool = False,
    quarantined_only: bool = False
):
    """List all registered agents"""
    db = SessionLocal()
    
    try:
        query = db.query(Agent)
        
        if status:
            query = query.filter(Agent.status == status)
        if moltbook_only:
            query = query.filter(Agent.moltbook_joined == True)
        if quarantined_only:
            query = query.filter(Agent.quarantined == True)
        
        agents = query.order_by(Agent.last_seen.desc()).all()
        
        return [AgentResponse(
            id=a.id,
            hostname=a.hostname,
            platform=a.platform,
            first_seen=a.first_seen,
            last_seen=a.last_seen,
            status=a.status,
            risk_score=a.risk_score,
            moltbook_joined=a.moltbook_joined,
            quarantined=a.quarantined
        ) for a in agents]
        
    finally:
        db.close()


@app.get("/api/v1/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(agent_id: str):
    """Get agent details"""
    db = SessionLocal()
    
    try:
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        return AgentResponse(
            id=agent.id,
            hostname=agent.hostname,
            platform=agent.platform,
            first_seen=agent.first_seen,
            last_seen=agent.last_seen,
            status=agent.status,
            risk_score=agent.risk_score,
            moltbook_joined=agent.moltbook_joined,
            quarantined=agent.quarantined
        )
        
    finally:
        db.close()


@app.post("/api/v1/agents/{agent_id}/quarantine")
async def quarantine_agent(agent_id: str, reason: str = "Manual quarantine"):
    """Manually quarantine an agent"""
    db = SessionLocal()
    
    try:
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        agent.quarantined = True
        agent.quarantine_reason = reason
        agent.status = AgentStatus.QUARANTINED
        
        # Create incident
        incident = Incident(
            agent_id=agent_id,
            severity='high',
            title='Manual Quarantine',
            description=reason,
            signals=[]
        )
        db.add(incident)
        db.commit()
        
        return {"status": "quarantined", "agent_id": agent_id}
        
    finally:
        db.close()


@app.post("/api/v1/agents/{agent_id}/release")
async def release_agent(agent_id: str):
    """Release an agent from quarantine"""
    db = SessionLocal()
    
    try:
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        agent.quarantined = False
        agent.quarantine_reason = None
        agent.status = AgentStatus.HEALTHY
        agent.risk_score = 0.0
        
        db.commit()
        
        return {"status": "released", "agent_id": agent_id}
        
    finally:
        db.close()


# --- Incidents ---

@app.get("/api/v1/incidents", response_model=list[IncidentResponse])
async def list_incidents(
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=100, le=500)
):
    """List security incidents"""
    db = SessionLocal()
    
    try:
        query = db.query(Incident)
        
        if agent_id:
            query = query.filter(Incident.agent_id == agent_id)
        if status:
            query = query.filter(Incident.status == status)
        if severity:
            query = query.filter(Incident.severity == severity)
        
        incidents = query.order_by(Incident.created_at.desc()).limit(limit).all()
        
        return [IncidentResponse(
            id=i.id,
            agent_id=i.agent_id,
            created_at=i.created_at,
            resolved_at=i.resolved_at,
            severity=i.severity,
            title=i.title,
            description=i.description,
            signals=i.signals or [],
            status=i.status
        ) for i in incidents]
        
    finally:
        db.close()


@app.post("/api/v1/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: str, resolution: str = "Resolved"):
    """Resolve an incident"""
    db = SessionLocal()
    
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        incident.status = "resolved"
        incident.resolution = resolution
        incident.resolved_at = datetime.now(timezone.utc)
        
        db.commit()
        
        return {"status": "resolved", "incident_id": incident_id}
        
    finally:
        db.close()


# --- Dashboard ---

@app.get("/api/v1/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """Get dashboard statistics"""
    db = SessionLocal()
    
    try:
        agents = db.query(Agent).all()
        
        total = len(agents)
        healthy = len([a for a in agents if a.status == AgentStatus.HEALTHY])
        warning = len([a for a in agents if a.status == AgentStatus.WARNING])
        compromised = len([a for a in agents if a.status == AgentStatus.COMPROMISED])
        quarantined = len([a for a in agents if a.quarantined])
        moltbook = len([a for a in agents if a.moltbook_joined])
        
        open_incidents = db.query(Incident).filter(Incident.status == "open").count()
        
        avg_risk = sum(a.risk_score for a in agents) / total if total > 0 else 0.0
        
        return DashboardStats(
            total_agents=total,
            healthy_agents=healthy,
            warning_agents=warning,
            compromised_agents=compromised,
            quarantined_agents=quarantined,
            moltbook_participants=moltbook,
            open_incidents=open_incidents,
            avg_risk_score=avg_risk
        )
        
    finally:
        db.close()


@app.get("/api/v1/dashboard/timeline")
async def get_timeline(hours: int = 24):
    """Get incident timeline"""
    db = SessionLocal()
    
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        incidents = db.query(Incident).filter(
            Incident.created_at >= cutoff
        ).order_by(Incident.created_at.desc()).all()
        
        return [{
            'id': i.id,
            'agent_id': i.agent_id,
            'timestamp': i.created_at.isoformat(),
            'severity': i.severity,
            'title': i.title,
            'status': i.status
        } for i in incidents]
        
    finally:
        db.close()


# --- Approved Hashes ---

@app.get("/api/v1/approved-hashes")
async def list_approved_hashes(agent_id: Optional[str] = None):
    """List approved file hashes"""
    db = SessionLocal()
    
    try:
        query = db.query(ApprovedHash)
        
        if agent_id:
            query = query.filter(
                (ApprovedHash.agent_id == agent_id) | (ApprovedHash.agent_id == None)
            )
        
        hashes = query.all()
        
        return [{
            'id': h.id,
            'agent_id': h.agent_id,
            'file_path_pattern': h.file_path_pattern,
            'hash_sha256': h.hash_sha256,
            'description': h.description,
            'approved_by': h.approved_by,
            'approved_at': h.approved_at.isoformat() if h.approved_at else None
        } for h in hashes]
        
    finally:
        db.close()


class ApproveHashRequest(BaseModel):
    file_path_pattern: str
    hash_sha256: str
    description: Optional[str] = None
    agent_id: Optional[str] = None  # null = global


@app.post("/api/v1/approved-hashes")
async def approve_hash(request: ApproveHashRequest):
    """Approve a file hash"""
    db = SessionLocal()
    
    try:
        approved = ApprovedHash(
            file_path_pattern=request.file_path_pattern,
            hash_sha256=request.hash_sha256,
            description=request.description,
            agent_id=request.agent_id,
            approved_by="admin"  # In production, get from auth
        )
        db.add(approved)
        db.commit()
        
        return {"status": "approved", "id": approved.id}
        
    finally:
        db.close()


# --- Health Check ---

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "version": "1.0.0"}


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
