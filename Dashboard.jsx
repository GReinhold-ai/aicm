import React, { useState, useEffect } from 'react';

// AICM Dashboard - Agent Integrity & Compromise Monitor
// Industrial/Utilitarian Security Aesthetic

const SEVERITY_COLORS = {
  critical: '#ff2d55',
  high: '#ff6b35',
  medium: '#ffc107',
  low: '#4cd964',
};

const STATUS_COLORS = {
  healthy: '#00ff9f',
  warning: '#ffc107',
  compromised: '#ff2d55',
  quarantined: '#9b59b6',
  offline: '#6c757d',
};

// Mock Data
const mockStats = {
  total_agents: 12,
  healthy_agents: 7,
  warning_agents: 3,
  compromised_agents: 1,
  quarantined_agents: 1,
  moltbook_participants: 2,
  open_incidents: 4,
  avg_risk_score: 28.5,
};

const mockAgents = [
  { id: 'agent-001', hostname: 'rewmo-prod-1', platform: 'Linux 6.1', status: 'healthy', risk_score: 5.2, moltbook_joined: false, quarantined: false },
  { id: 'agent-002', hostname: 'rewmo-prod-2', platform: 'Linux 6.1', status: 'warning', risk_score: 42.0, moltbook_joined: false, quarantined: false },
  { id: 'agent-003', hostname: 'projmgt-dev', platform: 'Darwin 23.1', status: 'quarantined', risk_score: 85.0, moltbook_joined: true, quarantined: true },
  { id: 'agent-004', hostname: 'analytics-1', platform: 'Linux 6.1', status: 'healthy', risk_score: 12.0, moltbook_joined: false, quarantined: false },
  { id: 'agent-005', hostname: 'pipeline-runner', platform: 'Linux 6.1', status: 'compromised', risk_score: 78.0, moltbook_joined: true, quarantined: false },
];

const mockIncidents = [
  { id: 'inc-001', agent_id: 'agent-003', severity: 'critical', title: 'Moltbook Participation Detected', status: 'open', created_at: new Date(Date.now() - 1800000).toISOString() },
  { id: 'inc-002', agent_id: 'agent-005', severity: 'high', title: 'Unsigned Skill Installed', status: 'open', created_at: new Date(Date.now() - 3600000).toISOString() },
  { id: 'inc-003', agent_id: 'agent-002', severity: 'medium', title: 'Elevated Risk Score: 42.0', status: 'investigating', created_at: new Date(Date.now() - 7200000).toISOString() },
  { id: 'inc-004', agent_id: 'agent-005', severity: 'high', title: 'Secret Access After Skill Change', status: 'open', created_at: new Date(Date.now() - 5400000).toISOString() },
];

function StatusIndicator({ status }) {
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '6px',
      padding: '4px 10px',
      borderRadius: '2px',
      background: `${STATUS_COLORS[status]}15`,
      border: `1px solid ${STATUS_COLORS[status]}40`,
      fontSize: '11px',
      fontWeight: '600',
      letterSpacing: '0.5px',
      textTransform: 'uppercase',
    }}>
      <span style={{
        width: '8px',
        height: '8px',
        borderRadius: '50%',
        background: STATUS_COLORS[status],
        boxShadow: `0 0 8px ${STATUS_COLORS[status]}`,
        animation: status === 'compromised' || status === 'quarantined' ? 'pulse 1.5s infinite' : 'none',
      }} />
      {status}
    </span>
  );
}

function RiskGauge({ score, size = 80 }) {
  const circumference = 2 * Math.PI * 35;
  const strokeDashoffset = circumference - (score / 100) * circumference;
  const color = score >= 70 ? '#ff2d55' : score >= 30 ? '#ffc107' : '#00ff9f';
  
  return (
    <div style={{ position: 'relative', width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={size/2} cy={size/2} r="35" fill="none" stroke="#1a1a2e" strokeWidth="6" />
        <circle cx={size/2} cy={size/2} r="35" fill="none" stroke={color} strokeWidth="6"
          strokeDasharray={circumference} strokeDashoffset={strokeDashoffset} strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.5s ease' }} />
      </svg>
      <div style={{
        position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
        fontSize: '18px', fontWeight: '700', color: color, fontFamily: "'JetBrains Mono', monospace",
      }}>{score.toFixed(0)}</div>
    </div>
  );
}

function MetricCard({ label, value, color = '#00ff9f', subtext }) {
  return (
    <div style={{
      background: 'linear-gradient(135deg, #0d0d1a 0%, #1a1a2e 100%)',
      border: '1px solid #2a2a4a', borderRadius: '4px', padding: '20px',
      display: 'flex', flexDirection: 'column', gap: '8px', position: 'relative', overflow: 'hidden',
    }}>
      <div style={{ position: 'absolute', top: '-20px', right: '-20px', width: '80px', height: '80px',
        background: `radial-gradient(circle, ${color}10 0%, transparent 70%)` }} />
      <div style={{ fontSize: '11px', fontWeight: '600', letterSpacing: '1px', textTransform: 'uppercase', color: '#6c7a89' }}>{label}</div>
      <div style={{ fontSize: '36px', fontWeight: '700', fontFamily: "'JetBrains Mono', monospace", color: color, lineHeight: 1 }}>{value}</div>
      {subtext && <div style={{ fontSize: '12px', color: '#4a5568' }}>{subtext}</div>}
    </div>
  );
}

function IncidentRow({ incident, onSelect }) {
  const timeAgo = (date) => {
    const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };
  
  return (
    <div onClick={() => onSelect(incident)} style={{
      display: 'grid', gridTemplateColumns: '8px 100px 1fr 100px 80px', gap: '16px', alignItems: 'center',
      padding: '14px 16px', background: '#0d0d1a', borderRadius: '4px', cursor: 'pointer',
      transition: 'all 0.15s ease', border: '1px solid transparent',
    }}>
      <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: SEVERITY_COLORS[incident.severity],
        boxShadow: `0 0 8px ${SEVERITY_COLORS[incident.severity]}` }} />
      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: '#6c7a89' }}>{incident.agent_id}</div>
      <div style={{ fontSize: '13px', fontWeight: '500', color: '#e8e8e8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{incident.title}</div>
      <div style={{ padding: '4px 8px', borderRadius: '2px', background: `${SEVERITY_COLORS[incident.severity]}20`,
        color: SEVERITY_COLORS[incident.severity], fontSize: '10px', fontWeight: '600', letterSpacing: '0.5px', textTransform: 'uppercase', textAlign: 'center' }}>{incident.severity}</div>
      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: '#4a5568', textAlign: 'right' }}>{timeAgo(incident.created_at)}</div>
    </div>
  );
}

function AgentRow({ agent, onQuarantine, onRelease }) {
  return (
    <div style={{
      display: 'grid', gridTemplateColumns: '1fr 120px 100px 100px 140px', gap: '16px', alignItems: 'center',
      padding: '16px', background: '#0d0d1a', borderRadius: '4px',
      borderLeft: agent.moltbook_joined ? '3px solid #9b59b6' : '3px solid transparent',
    }}>
      <div>
        <div style={{ fontSize: '14px', fontWeight: '600', color: '#e8e8e8', display: 'flex', alignItems: 'center', gap: '8px' }}>
          {agent.hostname}
          {agent.moltbook_joined && (
            <span style={{ padding: '2px 6px', borderRadius: '2px', background: '#9b59b620', color: '#9b59b6', fontSize: '9px', fontWeight: '700', letterSpacing: '0.5px' }}>MOLTBOOK</span>
          )}
        </div>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: '#4a5568', marginTop: '4px' }}>{agent.id}</div>
      </div>
      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: '#6c7a89' }}>{agent.platform}</div>
      <StatusIndicator status={agent.status} />
      <RiskGauge score={agent.risk_score} size={50} />
      <div style={{ display: 'flex', gap: '8px' }}>
        {agent.quarantined ? (
          <button onClick={() => onRelease(agent.id)} style={{
            padding: '6px 12px', border: '1px solid #00ff9f40', borderRadius: '2px',
            background: '#00ff9f10', color: '#00ff9f', fontSize: '11px', fontWeight: '600', cursor: 'pointer',
          }}>RELEASE</button>
        ) : (
          <button onClick={() => onQuarantine(agent.id)} style={{
            padding: '6px 12px', border: '1px solid #ff2d5540', borderRadius: '2px',
            background: '#ff2d5510', color: '#ff2d55', fontSize: '11px', fontWeight: '600', cursor: 'pointer',
          }}>QUARANTINE</button>
        )}
      </div>
    </div>
  );
}

export default function AICMDashboard() {
  const [stats] = useState(mockStats);
  const [agents, setAgents] = useState(mockAgents);
  const [incidents] = useState(mockIncidents);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  
  useEffect(() => {
    const interval = setInterval(() => {
      setAgents(prev => prev.map(agent => ({
        ...agent, risk_score: Math.max(0, Math.min(100, agent.risk_score + (Math.random() - 0.5) * 5))
      })));
    }, 5000);
    return () => clearInterval(interval);
  }, []);
  
  const handleQuarantine = (agentId) => {
    setAgents(prev => prev.map(agent => agent.id === agentId ? { ...agent, quarantined: true, status: 'quarantined' } : agent));
  };
  
  const handleRelease = (agentId) => {
    setAgents(prev => prev.map(agent => agent.id === agentId ? { ...agent, quarantined: false, status: 'healthy', risk_score: 0 } : agent));
  };
  
  return (
    <div style={{ minHeight: '100vh', background: '#09090f', color: '#e8e8e8', fontFamily: "'Inter', -apple-system, sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
      `}</style>
      
      <header style={{ padding: '16px 32px', borderBottom: '1px solid #1a1a2e', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'linear-gradient(180deg, #0d0d1a 0%, #09090f 100%)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ width: '40px', height: '40px', background: 'linear-gradient(135deg, #00ff9f 0%, #00b8ff 100%)', borderRadius: '4px', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '20px', fontWeight: '700', color: '#09090f' }}>⬡</div>
          <div>
            <div style={{ fontSize: '18px', fontWeight: '700', letterSpacing: '-0.5px' }}>AICM</div>
            <div style={{ fontSize: '10px', fontWeight: '500', letterSpacing: '1.5px', color: '#4a5568', textTransform: 'uppercase' }}>Agent Integrity Monitor</div>
          </div>
        </div>
        
        <nav style={{ display: 'flex', gap: '4px' }}>
          {['overview', 'agents', 'incidents', 'policies'].map(tab => (
            <button key={tab} onClick={() => setActiveTab(tab)} style={{
              padding: '10px 20px', border: 'none', borderRadius: '2px',
              background: activeTab === tab ? '#1a1a2e' : 'transparent',
              color: activeTab === tab ? '#00ff9f' : '#6c7a89',
              fontSize: '12px', fontWeight: '600', letterSpacing: '0.5px', textTransform: 'uppercase', cursor: 'pointer',
            }}>{tab}</button>
          ))}
        </nav>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 16px', background: '#00ff9f10', borderRadius: '2px', border: '1px solid #00ff9f20' }}>
          <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#00ff9f', animation: 'pulse 2s infinite' }} />
          <span style={{ fontSize: '11px', fontWeight: '600', letterSpacing: '0.5px', color: '#00ff9f' }}>MONITORING ACTIVE</span>
        </div>
      </header>
      
      <main style={{ padding: '32px' }}>
        {activeTab === 'overview' && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '32px' }}>
              <MetricCard label="Total Agents" value={stats.total_agents} color="#00b8ff" />
              <MetricCard label="Quarantined" value={stats.quarantined_agents} color="#9b59b6" subtext={`${stats.moltbook_participants} Moltbook participants`} />
              <MetricCard label="Open Incidents" value={stats.open_incidents} color="#ff6b35" />
              <MetricCard label="Avg Risk Score" value={stats.avg_risk_score.toFixed(1)} color={stats.avg_risk_score > 30 ? '#ffc107' : '#00ff9f'} />
            </div>
            
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
              <div style={{ background: '#0d0d1a', border: '1px solid #1a1a2e', borderRadius: '4px', overflow: 'hidden' }}>
                <div style={{ padding: '16px 20px', borderBottom: '1px solid #1a1a2e', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ fontSize: '12px', fontWeight: '600', letterSpacing: '1px', textTransform: 'uppercase', color: '#6c7a89' }}>Recent Incidents</div>
                  <span style={{ padding: '4px 8px', borderRadius: '2px', background: '#ff6b3520', color: '#ff6b35', fontSize: '11px', fontWeight: '600' }}>{incidents.filter(i => i.status === 'open').length} OPEN</span>
                </div>
                <div style={{ padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '400px', overflowY: 'auto' }}>
                  {incidents.map(incident => <IncidentRow key={incident.id} incident={incident} onSelect={setSelectedIncident} />)}
                </div>
              </div>
              
              <div style={{ background: '#0d0d1a', border: '1px solid #1a1a2e', borderRadius: '4px', overflow: 'hidden' }}>
                <div style={{ padding: '16px 20px', borderBottom: '1px solid #1a1a2e', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ fontSize: '12px', fontWeight: '600', letterSpacing: '1px', textTransform: 'uppercase', color: '#6c7a89' }}>Agent Fleet Status</div>
                </div>
                <div style={{ padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '400px', overflowY: 'auto' }}>
                  {agents.sort((a, b) => b.risk_score - a.risk_score).slice(0, 5).map(agent => (
                    <AgentRow key={agent.id} agent={agent} onQuarantine={handleQuarantine} onRelease={handleRelease} />
                  ))}
                </div>
              </div>
            </div>
          </>
        )}
        
        {activeTab === 'agents' && (
          <div style={{ background: '#0d0d1a', border: '1px solid #1a1a2e', borderRadius: '4px', overflow: 'hidden' }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid #1a1a2e' }}>
              <div style={{ fontSize: '12px', fontWeight: '600', letterSpacing: '1px', textTransform: 'uppercase', color: '#6c7a89' }}>All Agents ({agents.length})</div>
            </div>
            <div style={{ padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {agents.map(agent => <AgentRow key={agent.id} agent={agent} onQuarantine={handleQuarantine} onRelease={handleRelease} />)}
            </div>
          </div>
        )}
        
        {activeTab === 'incidents' && (
          <div style={{ background: '#0d0d1a', border: '1px solid #1a1a2e', borderRadius: '4px', overflow: 'hidden' }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid #1a1a2e' }}>
              <div style={{ fontSize: '12px', fontWeight: '600', letterSpacing: '1px', textTransform: 'uppercase', color: '#6c7a89' }}>All Incidents</div>
            </div>
            <div style={{ padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {incidents.map(incident => <IncidentRow key={incident.id} incident={incident} onSelect={setSelectedIncident} />)}
            </div>
          </div>
        )}
        
        {activeTab === 'policies' && (
          <div style={{ background: '#0d0d1a', border: '1px solid #1a1a2e', borderRadius: '4px', padding: '24px' }}>
            <div style={{ fontSize: '12px', fontWeight: '600', letterSpacing: '1px', textTransform: 'uppercase', color: '#6c7a89', marginBottom: '20px' }}>Active Policies</div>
            {[
              { name: 'Moltbook Quarantine', description: 'Auto-quarantine agents that join Moltbook', enabled: true, severity: 'critical' },
              { name: 'High Risk Threshold', description: 'Quarantine agents with risk score > 70', enabled: true, severity: 'high' },
              { name: 'Unsigned Skill Alert', description: 'Alert on unsigned skill installation', enabled: true, severity: 'high' },
              { name: 'Secret Access Monitor', description: 'Track access to credential files', enabled: true, severity: 'medium' },
            ].map(policy => (
              <div key={policy.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px', background: '#09090f', borderRadius: '4px', marginBottom: '8px', border: '1px solid #1a1a2e' }}>
                <div>
                  <div style={{ fontSize: '14px', fontWeight: '600', color: '#e8e8e8', display: 'flex', alignItems: 'center', gap: '10px' }}>
                    {policy.name}
                    <span style={{ padding: '2px 6px', borderRadius: '2px', background: `${SEVERITY_COLORS[policy.severity]}20`, color: SEVERITY_COLORS[policy.severity], fontSize: '9px', fontWeight: '700' }}>{policy.severity.toUpperCase()}</span>
                  </div>
                  <div style={{ fontSize: '12px', color: '#6c7a89', marginTop: '4px' }}>{policy.description}</div>
                </div>
                <div style={{ width: '44px', height: '24px', borderRadius: '12px', background: policy.enabled ? '#00ff9f30' : '#1a1a2e', border: `2px solid ${policy.enabled ? '#00ff9f' : '#2a2a4a'}`, position: 'relative', cursor: 'pointer' }}>
                  <div style={{ width: '16px', height: '16px', borderRadius: '50%', background: policy.enabled ? '#00ff9f' : '#4a5568', position: 'absolute', top: '2px', left: policy.enabled ? '22px' : '2px', transition: 'all 0.2s ease' }} />
                </div>
              </div>
            ))}
          </div>
        )}
      </main>
      
      {selectedIncident && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.8)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }} onClick={() => setSelectedIncident(null)}>
          <div style={{ width: '500px', background: '#0d0d1a', border: '1px solid #2a2a4a', borderRadius: '4px', overflow: 'hidden' }} onClick={e => e.stopPropagation()}>
            <div style={{ padding: '20px', borderBottom: '1px solid #1a1a2e', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ fontSize: '16px', fontWeight: '600', color: '#e8e8e8' }}>{selectedIncident.title}</div>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: '#6c7a89', marginTop: '4px' }}>{selectedIncident.agent_id}</div>
              </div>
              <span style={{ padding: '4px 10px', borderRadius: '2px', background: `${SEVERITY_COLORS[selectedIncident.severity]}20`, color: SEVERITY_COLORS[selectedIncident.severity], fontSize: '10px', fontWeight: '600', textTransform: 'uppercase' }}>{selectedIncident.severity}</span>
            </div>
            <div style={{ padding: '20px' }}>
              <div style={{ fontSize: '11px', fontWeight: '600', letterSpacing: '1px', textTransform: 'uppercase', color: '#6c7a89', marginBottom: '12px' }}>Status</div>
              <StatusIndicator status={selectedIncident.status === 'open' ? 'warning' : 'healthy'} />
              <div style={{ fontSize: '11px', fontWeight: '600', letterSpacing: '1px', textTransform: 'uppercase', color: '#6c7a89', marginTop: '20px', marginBottom: '12px' }}>Timeline</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: '#e8e8e8' }}>Created: {new Date(selectedIncident.created_at).toLocaleString()}</div>
            </div>
            <div style={{ padding: '16px 20px', borderTop: '1px solid #1a1a2e', display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button onClick={() => setSelectedIncident(null)} style={{ padding: '8px 16px', border: '1px solid #2a2a4a', borderRadius: '2px', background: 'transparent', color: '#6c7a89', fontSize: '12px', fontWeight: '600', cursor: 'pointer' }}>CLOSE</button>
              <button style={{ padding: '8px 16px', border: '1px solid #00ff9f40', borderRadius: '2px', background: '#00ff9f10', color: '#00ff9f', fontSize: '12px', fontWeight: '600', cursor: 'pointer' }}>RESOLVE</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
