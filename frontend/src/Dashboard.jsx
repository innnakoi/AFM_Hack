import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts';
import {
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  Clock3,
  Cpu,
  Database,
  Eye,
  FileWarning,
  Fingerprint,
  Lock,
  MailWarning,
  Network,
  PlayCircle,
  Radar,
  RefreshCw,
  Shield,
  ShieldAlert,
  Siren,
  Sparkles,
  TerminalSquare,
  UserX,
  Workflow,
  Zap
} from 'lucide-react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000/api';

const fallbackFeed = {
  mode: 'defend',
  overall_risk: 89,
  risk_level: 'HIGH',
  mean_detect_time_seconds: 0.9,
  blocked_data_gb: 1.7,
  protected_assets: 1248,
  active_incidents: 3,
  device_context: {
    cpu_percent: 41,
    memory_percent: 58,
    disk_percent: 37,
    active_processes: 0,
    network_connections: 0,
    suspicious_ips: [],
    process_watchlist: [],
    remote_connections: [],
    analysis_basis: [
      'Live CPU, RAM, disk, process, and connection telemetry from the monitored device.',
      'Process priority is ranked by CPU and resident memory footprint.',
      'Network evidence is sampled from current remote connections.'
    ]
  },
  coverage: [
    { name: 'Unauthorized access', value: 96 },
    { name: 'User anomalies', value: 91 },
    { name: 'Data leaks', value: 88 },
    { name: 'Phishing', value: 86 },
    { name: 'Endpoint compromise', value: 74 }
  ],
  timeline: [
    { time: '13:21:43', event: 'AI correlated IAM, DLP, email, and endpoint signals.' },
    { time: '13:22:08', event: 'DLP blocked finance-q2.zip export to an external domain.' },
    { time: '13:22:35', event: 'Mail gateway quarantined 42 phishing messages.' },
    { time: '13:23:01', event: 'Step-up MFA was required for a risky user session.' },
    { time: '13:23:21', event: 'Endpoint-117 switched to evidence collection mode.' }
  ],
  signals: [
    {
      id: 'INC-2406-017',
      category: 'Unauthorized access',
      title: 'Possible account takeover',
      severity: 'CRITICAL',
      confidence: 94,
      risk_score: 92,
      source: 'vpn-gw-02 / iam',
      summary: 'User session combines impossible travel, new device fingerprint, and admin-scope access request.',
      evidence: [
        'Login from a new country occurred minutes after a local session.',
        'The session requested finance workspace and OAuth application permissions.',
        "Behavior differs from the user's 30-day baseline by time, geo, and device."
      ],
      factors: [
        { name: 'Geo anomaly', weight: 96 },
        { name: 'Privilege request', weight: 88 },
        { name: 'Device mismatch', weight: 81 }
      ],
      recommended_actions: ['Require step-up MFA', 'Revoke active tokens', 'Open SOC incident'],
      status: 'Containment ready'
    },
    {
      id: 'INC-2406-018',
      category: 'Data leak prevention',
      title: 'Sensitive archive export blocked',
      severity: 'HIGH',
      confidence: 91,
      risk_score: 87,
      source: 'cloud-storage / dlp',
      summary: 'DLP detected customer PII inside an archive sent to a low-reputation external domain.',
      evidence: [
        'Archive contains passport-like IDs, phone numbers, and email addresses.',
        'Recipient domain has no trusted exchange history with the organization.',
        'Upload volume is 11x higher than the department baseline.'
      ],
      factors: [
        { name: 'PII density', weight: 93 },
        { name: 'External domain', weight: 86 },
        { name: 'Upload burst', weight: 82 }
      ],
      recommended_actions: ['Block file transfer', 'Notify data owner', 'Preserve audit trail'],
      status: 'Blocked'
    },
    {
      id: 'INC-2406-019',
      category: 'Phishing',
      title: 'Credential phishing campaign',
      severity: 'HIGH',
      confidence: 86,
      risk_score: 79,
      source: 'mail-sec / gateway',
      summary: 'Email cluster imitates corporate SSO and asks users to approve a suspicious OAuth token.',
      evidence: [
        'Lookalike domain differs from the trusted domain by one character.',
        'Landing page requests OAuth consent outside the corporate SSO flow.',
        'The same template was delivered to 42 inboxes.'
      ],
      factors: [
        { name: 'Lookalike domain', weight: 90 },
        { name: 'Token request', weight: 84 },
        { name: 'Sender reputation', weight: 75 }
      ],
      recommended_actions: ['Quarantine messages', 'Block sender domain', 'Reset exposed passwords'],
      status: 'Quarantined'
    }
  ]
};

const categoryIcons = {
  'Unauthorized access': UserX,
  'Data leak prevention': Database,
  Phishing: MailWarning,
  'Endpoint behavior': TerminalSquare
};

const severityClass = {
  CRITICAL: 'bg-red-500/15 text-red-200 border-red-400/40',
  HIGH: 'bg-amber-500/15 text-amber-100 border-amber-400/40',
  MEDIUM: 'bg-sky-500/15 text-sky-100 border-sky-400/40',
  LOW: 'bg-emerald-500/15 text-emerald-100 border-emerald-400/40'
};

const sections = [
  {
    id: 'threat-center',
    label: 'Threat Center',
    icon: Siren,
    categories: null,
    description: 'All correlated incidents and device-backed AI decisions'
  },
  {
    id: 'access-ai',
    label: 'Access AI',
    icon: Fingerprint,
    categories: ['Unauthorized access'],
    description: 'Unauthorized access and abnormal user behavior'
  },
  {
    id: 'dlp-control',
    label: 'DLP Control',
    icon: FileWarning,
    categories: ['Data leak prevention'],
    description: 'Sensitive data exposure and export control'
  },
  {
    id: 'phishing-lab',
    label: 'Phishing Lab',
    icon: MailWarning,
    categories: ['Phishing'],
    description: 'Phishing, credential capture, and malicious mail patterns'
  },
  {
    id: 'response',
    label: 'Response',
    icon: Lock,
    categories: null,
    description: 'Playbook actions, containment, and analyst follow-up'
  }
];

function cx(...classes) {
  return classes.filter(Boolean).join(' ');
}

function StatCard({ label, value, note, icon: Icon, tone }) {
  return (
    <div className="rounded-lg border border-slate-700/80 bg-slate-900/72 p-4 shadow-xl shadow-black/20">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs uppercase tracking-wide text-slate-400">{label}</p>
          <p className={cx('mt-2 text-3xl font-black', tone)}>{value}</p>
        </div>
        <div className="grid h-10 w-10 place-items-center rounded-lg border border-cyan-300/20 bg-cyan-300/10 text-cyan-200">
          <Icon className="h-5 w-5" />
        </div>
      </div>
      <p className="mt-3 text-sm text-slate-400">{note}</p>
    </div>
  );
}

function SectionCard({ children, className = '' }) {
  return (
    <div className={cx('rounded-lg border border-slate-700/80 bg-slate-900/72 p-4 shadow-xl shadow-black/20', className)}>
      {children}
    </div>
  );
}

function ProgressRow({ label, value, tone = 'bg-cyan-300' }) {
  return (
    <div>
      <div className="mb-1 flex justify-between text-xs text-slate-400">
        <span>{label}</span>
        <span>{value}%</span>
      </div>
      <div className="h-2 rounded-full bg-slate-800">
        <div className={cx('h-2 rounded-full', tone)} style={{ width: `${value}%` }} />
      </div>
    </div>
  );
}

function SignalWorklist({ signals, selectedId, onSelect }) {
  if (!signals.length) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4 text-sm text-slate-400">
        No active incidents in this area.
      </div>
    );
  }

  return (
    <div className="grid gap-3">
      {signals.map((signal) => {
        const Icon = categoryIcons[signal.category] || Eye;
        return (
          <button
            key={signal.id}
            onClick={() => onSelect(signal.id)}
            className={cx(
              'rounded-lg border p-3 text-left transition',
              selectedId === signal.id
                ? 'border-cyan-300/50 bg-cyan-300/10'
                : 'border-slate-800 bg-slate-950/40 hover:border-slate-600'
            )}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex gap-3">
                <div className="grid h-9 w-9 place-items-center rounded-lg border border-slate-700 bg-slate-900 text-cyan-200">
                  <Icon className="h-4 w-4" />
                </div>
                <div>
                  <p className="font-semibold">{signal.title}</p>
                  <p className="mt-1 text-xs text-slate-400">{signal.source}</p>
                </div>
              </div>
              <span className={cx('rounded-full border px-2 py-1 text-xs font-bold', severityClass[signal.severity])}>
                {signal.risk_score}
              </span>
            </div>
          </button>
        );
      })}
    </div>
  );
}

function ActionButtons({ actions, onAction }) {
  return (
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
      {actions.map((action, index) => (
        <button
          key={action}
          onClick={() => onAction(action)}
          className={cx(
            'min-h-10 rounded-lg border px-3 text-sm font-bold',
            index === 0
              ? 'border-cyan-300 bg-cyan-300 text-slate-950'
              : 'border-slate-700 bg-slate-950 text-slate-200 hover:border-cyan-300/50'
          )}
        >
          {action}
        </button>
      ))}
    </div>
  );
}

function AccessTab({ signals, processes, status, selectedId, onSelect, onAction }) {
  const primarySignal = signals[0];
  const topProcesses = processes.slice(0, 6);

  return (
    <section className="grid grid-cols-1 gap-5 2xl:grid-cols-[1fr_.8fr]">
      <div className="grid gap-5">
        <SectionCard>
          <div className="mb-4 flex items-start justify-between gap-3">
            <div>
              <h3 className="font-bold">Identity Risk Control</h3>
              <p className="text-sm text-slate-400">Sessions, privilege requests, device changes, and baseline drift</p>
            </div>
            <Fingerprint className="h-5 w-5 text-cyan-200" />
          </div>

          <div className="grid gap-3 md:grid-cols-3">
            <div className="rounded-lg border border-red-400/30 bg-red-400/10 p-4">
              <p className="text-xs uppercase tracking-wide text-red-100">Account takeover</p>
              <p className="mt-2 text-3xl font-black text-red-100">{primarySignal?.risk_score || 0}</p>
              <p className="mt-2 text-sm text-slate-300">risk score</p>
            </div>
            <div className="rounded-lg border border-cyan-300/25 bg-cyan-300/10 p-4">
              <p className="text-xs uppercase tracking-wide text-cyan-100">Active processes</p>
              <p className="mt-2 text-3xl font-black text-cyan-100">{status?.active_processes || topProcesses.length}</p>
              <p className="mt-2 text-sm text-slate-300">local telemetry</p>
            </div>
            <div className="rounded-lg border border-emerald-300/25 bg-emerald-300/10 p-4">
              <p className="text-xs uppercase tracking-wide text-emerald-100">Decision</p>
              <p className="mt-2 text-2xl font-black text-emerald-100">MFA</p>
              <p className="mt-2 text-sm text-slate-300">step-up required</p>
            </div>
          </div>
        </SectionCard>

        <SectionCard>
          <h3 className="mb-1 font-bold">Access Incidents</h3>
          <p className="mb-3 text-sm text-slate-400">Click a signal to load its explanation and response actions</p>
          <SignalWorklist signals={signals} selectedId={selectedId} onSelect={onSelect} />
        </SectionCard>
      </div>

      <SectionCard>
        <h3 className="mb-3 font-bold">Host Context</h3>
        <div className="grid gap-3">
          {topProcesses.map((process) => (
            <div key={`${process.pid}-${process.name}`} className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold">{process.name}</p>
                  <p className="text-xs text-slate-500">PID {process.pid}</p>
                </div>
                <Cpu className="h-4 w-4 text-cyan-200" />
              </div>
              <div className="mt-3 grid grid-cols-2 gap-3 text-xs text-slate-400">
                <span>CPU {Number(process.cpu_percent || 0).toFixed(1)}%</span>
                <span>RAM {Number(process.memory_percent || 0).toFixed(1)}%</span>
              </div>
            </div>
          ))}
          {!topProcesses.length && (
            <p className="rounded-lg border border-slate-800 bg-slate-950/50 p-4 text-sm text-slate-400">
              Backend process telemetry is not available yet.
            </p>
          )}
        </div>
        {primarySignal && (
          <div className="mt-4 border-t border-slate-800 pt-4">
            <ActionButtons actions={primarySignal.recommended_actions} onAction={onAction} />
          </div>
        )}
      </SectionCard>
    </section>
  );
}

function DlpTab({ signals, feed, selectedId, onSelect, onAction }) {
  const primarySignal = signals[0];

  return (
    <section className="grid grid-cols-1 gap-5 2xl:grid-cols-[.85fr_1fr]">
      <SectionCard>
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h3 className="font-bold">Data Leak Prevention</h3>
            <p className="text-sm text-slate-400">Sensitive exports, external domains, and upload bursts</p>
          </div>
          <FileWarning className="h-5 w-5 text-amber-100" />
        </div>

        <div className="grid gap-3">
          <div className="rounded-lg border border-amber-300/30 bg-amber-300/10 p-4">
            <p className="text-xs uppercase tracking-wide text-amber-100">Blocked data</p>
            <p className="mt-2 text-3xl font-black text-amber-100">{feed.blocked_data_gb}GB</p>
            <p className="mt-2 text-sm text-slate-300">stopped before exfiltration</p>
          </div>
          {primarySignal?.factors.map((factor) => (
            <ProgressRow key={factor.name} label={factor.name} value={factor.weight} tone="bg-amber-300" />
          ))}
        </div>

        {primarySignal && (
          <div className="mt-5">
            <ActionButtons actions={primarySignal.recommended_actions} onAction={onAction} />
          </div>
        )}
      </SectionCard>

      <div className="grid gap-5">
        <SectionCard>
          <h3 className="mb-1 font-bold">DLP Worklist</h3>
          <p className="mb-3 text-sm text-slate-400">Incidents with sensitive data movement indicators</p>
          <SignalWorklist signals={signals} selectedId={selectedId} onSelect={onSelect} />
        </SectionCard>

        <SectionCard>
          <h3 className="mb-1 font-bold">Coverage by Control</h3>
          <p className="mb-3 text-sm text-slate-400">AI coverage across detection surfaces</p>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={feed.coverage} margin={{ left: 0, right: 8, top: 4, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 11 }} />
                <YAxis stroke="#94a3b8" domain={[0, 100]} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155' }} />
                <Bar dataKey="value" fill="#fcd34d" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </SectionCard>
      </div>
    </section>
  );
}

function PhishingTab({ signals, connections, selectedId, onSelect, onAction }) {
  const primarySignal = signals[0];

  return (
    <section className="grid grid-cols-1 gap-5 2xl:grid-cols-[1fr_.8fr]">
      <div className="grid gap-5">
        <SectionCard>
          <div className="mb-4 flex items-start justify-between gap-3">
            <div>
              <h3 className="font-bold">Phishing Campaign Lab</h3>
              <p className="text-sm text-slate-400">Lookalike domains, sender reputation, and OAuth abuse</p>
            </div>
            <MailWarning className="h-5 w-5 text-cyan-200" />
          </div>

          <div className="grid gap-3 md:grid-cols-3">
            <div className="rounded-lg border border-cyan-300/25 bg-cyan-300/10 p-4">
              <p className="text-xs uppercase tracking-wide text-cyan-100">Campaigns</p>
              <p className="mt-2 text-3xl font-black text-cyan-100">{signals.length}</p>
            </div>
            <div className="rounded-lg border border-red-400/30 bg-red-400/10 p-4">
              <p className="text-xs uppercase tracking-wide text-red-100">Risk score</p>
              <p className="mt-2 text-3xl font-black text-red-100">{primarySignal?.risk_score || 0}</p>
            </div>
            <div className="rounded-lg border border-emerald-300/25 bg-emerald-300/10 p-4">
              <p className="text-xs uppercase tracking-wide text-emerald-100">Gateway state</p>
              <p className="mt-2 text-2xl font-black text-emerald-100">{primarySignal?.status || 'Clean'}</p>
            </div>
          </div>
        </SectionCard>

        <SectionCard>
          <h3 className="mb-1 font-bold">Phishing Worklist</h3>
          <p className="mb-3 text-sm text-slate-400">Campaigns ready for quarantine and domain blocking</p>
          <SignalWorklist signals={signals} selectedId={selectedId} onSelect={onSelect} />
        </SectionCard>
      </div>

      <SectionCard>
        <h3 className="mb-3 font-bold">Artifacts</h3>
        <div className="grid gap-3">
          {primarySignal?.evidence.map((item) => (
            <p key={item} className="flex gap-2 rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-sm leading-5 text-slate-300">
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
              {item}
            </p>
          ))}
          <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
            <div className="mb-2 flex items-center gap-2 text-sm font-bold">
              <Network className="h-4 w-4 text-cyan-200" />
              Network context
            </div>
            <p className="text-sm text-slate-400">
              {connections.length} active connections are available for correlation with sender infrastructure.
            </p>
          </div>
        </div>
        {primarySignal && (
          <div className="mt-4 border-t border-slate-800 pt-4">
            <ActionButtons actions={primarySignal.recommended_actions} onAction={onAction} />
          </div>
        )}
      </SectionCard>
    </section>
  );
}

function ResponseTab({ selectedSignal, analysis, analysisActions, actionLog, socEvents, analyzing, onAnalyze, onAction }) {
  return (
    <section className="grid grid-cols-1 gap-5 2xl:grid-cols-[.9fr_1.1fr]">
      <SectionCard>
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h3 className="font-bold">AI Response Playbook</h3>
            <p className="text-sm text-slate-400">Recommended actions are generated from incident evidence and live analysis</p>
          </div>
          <Workflow className="h-5 w-5 text-cyan-200" />
        </div>

        <button
          onClick={onAnalyze}
          disabled={analyzing}
          className="mb-4 flex h-11 w-full items-center justify-center gap-2 rounded-lg border border-cyan-300 bg-cyan-300 px-4 text-sm font-bold text-slate-950 disabled:cursor-not-allowed disabled:opacity-70"
        >
          <PlayCircle className="h-4 w-4" />
          {analyzing ? 'Running analysis...' : 'Run AI analysis'}
        </button>

        <div className="grid gap-3">
          {analysisActions.map((action) => (
            <button
              key={action}
              onClick={() => onAction(action)}
              className="rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-left text-sm font-semibold text-slate-200 hover:border-cyan-300/50"
            >
              {action}
            </button>
          ))}
        </div>

        {analysis && (
          <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950/50 p-3">
            <p className="text-xs uppercase tracking-wide text-slate-400">Latest analysis</p>
            <p className="mt-2 text-lg font-black text-red-100">
              {analysis.threat_analysis?.threat_level || 'UNKNOWN'} / {Math.round((analysis.threat_analysis?.threat_score || 0) * 100)}%
            </p>
            <p className="mt-2 text-sm text-slate-300">{analysis.alert?.description || 'Analysis completed.'}</p>
          </div>
        )}
      </SectionCard>

      <div className="grid gap-5">
        <SectionCard>
          <h3 className="mb-1 font-bold">Selected Incident</h3>
          <p className="mb-3 text-sm text-slate-400">{selectedSignal.id} / {selectedSignal.category}</p>
          <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-lg font-black text-red-100">{selectedSignal.title}</p>
                <p className="mt-2 text-sm leading-6 text-slate-300">{selectedSignal.summary}</p>
              </div>
              <span className={cx('rounded-full border px-3 py-1 text-xs font-bold', severityClass[selectedSignal.severity])}>
                {selectedSignal.confidence}%
              </span>
            </div>
            <div className="mt-4">
              <ActionButtons actions={selectedSignal.recommended_actions} onAction={onAction} />
            </div>
          </div>
        </SectionCard>

        <SectionCard>
          <h3 className="mb-3 font-bold">Action Log</h3>
          <div className="grid gap-3">
            {actionLog.map((entry) => (
              <div key={entry.id} className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold">{entry.action}</p>
                    <p className="mt-1 text-xs text-slate-500">{entry.signalId} / {entry.category}</p>
                  </div>
                  <span className="text-xs text-cyan-200">{entry.time}</span>
                </div>
              </div>
            ))}
            {!actionLog.length && (
              <p className="rounded-lg border border-slate-800 bg-slate-950/50 p-4 text-sm text-slate-400">
                No response actions have been added yet.
              </p>
            )}
          </div>
        </SectionCard>

        <SectionCard>
          <h3 className="mb-1 font-bold">SOC Dataset Events</h3>
          <p className="mb-3 text-sm text-slate-400">Normalized OTRF events loaded into replay mode</p>
          <div className="grid max-h-96 gap-3 overflow-auto pr-1">
            {socEvents.map((event) => (
              <div key={event.id} className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-semibold">{event.title}</p>
                    <p className="mt-1 text-xs text-slate-500">
                      {event.host} / {event.user} / EventID {event.event_id}
                    </p>
                    <p className="mt-2 line-clamp-2 text-xs text-slate-400">{event.summary}</p>
                  </div>
                  <span className={cx('shrink-0 rounded-full border px-2 py-1 text-xs font-bold', severityClass[event.severity])}>
                    {event.risk_score}
                  </span>
                </div>
              </div>
            ))}
            {!socEvents.length && (
              <p className="rounded-lg border border-slate-800 bg-slate-950/50 p-4 text-sm text-slate-400">
                Load SOC data to replay real OTRF events here.
              </p>
            )}
          </div>
        </SectionCard>
      </div>
    </section>
  );
}

function LoadingScreen() {
  return (
    <div className="grid min-h-screen place-items-center bg-slate-950 text-slate-100">
      <div className="text-center">
        <Shield className="mx-auto h-12 w-12 animate-pulse text-cyan-300" />
        <p className="mt-4 text-sm text-slate-300">AI Shield Guardian is starting threat intelligence...</p>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [status, setStatus] = useState(null);
  const [feed, setFeed] = useState(fallbackFeed);
  const [selectedId, setSelectedId] = useState(fallbackFeed.signals[0].id);
  const [activeTab, setActiveTab] = useState('threat');
  const [selectedMode, setSelectedMode] = useState(fallbackFeed.mode);
  const [processes, setProcesses] = useState([]);
  const [connections, setConnections] = useState([]);
  const [analysis, setAnalysis] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [actionLog, setActionLog] = useState([]);
  const [socInfo, setSocInfo] = useState(null);
  const [socEvents, setSocEvents] = useState([]);
  const [socLoading, setSocLoading] = useState(false);
  const [chartData, setChartData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState('');
  const [actionLog, setActionLog] = useState([]);

  const currentSection = useMemo(() => {
    return sections.find((section) => section.id === activeSection) || sections[0];
  }, [activeSection]);

  const visibleSignals = useMemo(() => {
    if (!currentSection.categories) {
      return feed.signals;
    }
    return feed.signals.filter((signal) => currentSection.categories.includes(signal.category));
  }, [feed.signals, currentSection]);

  const accessSignals = useMemo(
    () => feed.signals.filter((signal) => signal.category === 'Unauthorized access'),
    [feed.signals]
  );
  const dlpSignals = useMemo(
    () => feed.signals.filter((signal) => signal.category === 'Data leak prevention'),
    [feed.signals]
  );
  const phishingSignals = useMemo(
    () => feed.signals.filter((signal) => signal.category === 'Phishing'),
    [feed.signals]
  );

  const selectedSignal = useMemo(() => {
    return visibleSignals.find((signal) => signal.id === selectedId) || visibleSignals[0] || feed.signals[0];
  }, [feed.signals, selectedId, visibleSignals]);

  const sectionCounts = useMemo(() => {
    return sections.reduce((acc, section) => {
      acc[section.id] = section.categories
        ? feed.signals.filter((signal) => section.categories.includes(signal.category)).length
        : feed.signals.length;
      return acc;
    }, {});
  }, [feed.signals]);

  const analysisActions = useMemo(() => {
    const actions = new Set(selectedSignal.recommended_actions);
    if (analysis?.threat_analysis?.threat_level) {
      const level = analysis.threat_analysis.threat_level;
      if (['HIGH', 'CRITICAL'].includes(level)) {
        actions.add('Isolate high-risk host');
        actions.add('Escalate to SOC lead');
      }
      if ((analysis.high_risk_processes || []).length) {
        actions.add('Review high-risk processes');
      }
      if ((analysis.network_anomalies || []).length) {
        actions.add('Block suspicious network destinations');
      }
    } else {
      actions.add('Run AI analysis');
      actions.add('Prepare incident report');
    }
    return Array.from(actions).slice(0, 6);
  }, [analysis, selectedSignal]);

  const tabDefinitions = useMemo(() => ([
    {
      id: 'threat',
      label: 'Threat Center',
      count: feed.active_incidents,
      icon: Siren,
      title: 'Threat Detection & Response',
      description: 'Detects unauthorized access, abnormal users, data leaks, phishing, and compromise indicators in real time.'
    },
    {
      id: 'access',
      label: 'Access AI',
      count: accessSignals.length,
      icon: Fingerprint,
      title: 'Access AI',
      description: 'Tracks risky sessions, suspicious privilege requests, impossible travel, and device mismatches.'
    },
    {
      id: 'dlp',
      label: 'DLP Control',
      count: dlpSignals.length,
      icon: FileWarning,
      title: 'DLP Control',
      description: 'Explains sensitive data movement, external sharing, and blocked exfiltration attempts.'
    },
    {
      id: 'phishing',
      label: 'Phishing Lab',
      count: phishingSignals.length,
      icon: MailWarning,
      title: 'Phishing Lab',
      description: 'Investigates phishing campaigns, malicious senders, lookalike domains, and inbox quarantine.'
    },
    {
      id: 'response',
      label: 'Response',
      count: actionLog.length || analysisActions.length,
      icon: Lock,
      title: 'AI Response',
      description: 'Turns the current analysis into recommended response steps and analyst-ready actions.'
    }
  ]), [accessSignals.length, actionLog.length, analysisActions.length, dlpSignals.length, feed.active_incidents, phishingSignals.length]);

  const activeTabMeta = tabDefinitions.find((tab) => tab.id === activeTab) || tabDefinitions[0];

  const fetchDashboardData = useCallback(async () => {
    try {
      const [statusRes, feedRes, processesRes, connectionsRes, socInfoRes, socEventsRes] = await Promise.all([
        axios.get(`${API_BASE}/status`),
        axios.get(`${API_BASE}/security-feed`),
        axios.get(`${API_BASE}/processes`),
        axios.get(`${API_BASE}/connections`),
        axios.get(`${API_BASE}/soc/datasets`),
        axios.get(`${API_BASE}/soc/events?limit=40`)
      ]);

      setStatus(statusRes.data);
      setFeed(feedRes.data);
      setProcesses(processesRes.data || []);
      setConnections(connectionsRes.data?.connections || []);
      setSocInfo(socInfoRes.data);
      setSocEvents(socEventsRes.data?.events || []);
      setSelectedMode((current) => current || feedRes.data.mode);
      setSelectedId((current) => {
        const exists = feedRes.data.signals.some((signal) => signal.id === current);
        return exists ? current : feedRes.data.signals[0]?.id;
      });
      setDefenseMode((current) => current || feedRes.data.mode || 'defend');
      setChartData((prev) => [
        ...prev,
        {
          time: new Date().toLocaleTimeString(),
          risk: feedRes.data.overall_risk,
          confidence: feedRes.data.signals[0]?.confidence || 0,
          cpu: statusRes.data.cpu_percent,
          memory: statusRes.data.memory_percent
        }
      ].slice(-14));
    } catch (error) {
      setChartData((prev) => [
        ...prev,
        {
          time: new Date().toLocaleTimeString(),
          risk: fallbackFeed.overall_risk,
          confidence: fallbackFeed.signals[0].confidence,
          cpu: 41,
          memory: 58
        }
      ].slice(-14));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 5000);
    return () => clearInterval(interval);
  }, [fetchDashboardData]);

  const runAction = (action) => {
    const entry = {
      id: `${Date.now()}-${action}`,
      action,
      signalId: selectedSignal.id,
      category: selectedSignal.category,
      time: new Date().toLocaleTimeString()
    };
    setActionLog((current) => [entry, ...current].slice(0, 10));
    setNotice(`${action}: action added to response playbook`);
    return window.setTimeout(() => setNotice(''), 2600);
  };

  const runFullAnalysis = async () => {
    setAnalyzing(true);
    try {
      const response = await axios.post(`${API_BASE}/analyze`);
      setAnalysis(response.data);
      setNotice('AI analysis completed and recommendations refreshed');
    } catch (error) {
      setNotice('AI analysis is unavailable: check backend connection');
    } finally {
      setAnalyzing(false);
      window.setTimeout(() => setNotice(''), 2600);
    }
  };

  const loadSocDataset = async () => {
    setSocLoading(true);
    try {
      const response = await axios.post(`${API_BASE}/soc/load`, {
        dataset_id: 'all',
        max_events: 1600
      });
      setFeed(response.data.feed);
      setSocEvents(response.data.top_events || []);
      setSocInfo((current) => ({
        ...(current || {}),
        active_dataset_id: response.data.dataset_id,
        active_event_count: response.data.event_count
      }));
      setNotice(`${response.data.event_count} real SOC events loaded`);
      await fetchDashboardData();
    } catch (error) {
      setNotice('SOC dataset load failed: check backend/data/otrf');
    } finally {
      setSocLoading(false);
      window.setTimeout(() => setNotice(''), 3200);
    }
  };

  const clearSocDataset = async () => {
    setSocLoading(true);
    try {
      await axios.post(`${API_BASE}/soc/clear`);
      setSocEvents([]);
      setSocInfo((current) => ({
        ...(current || {}),
        active_dataset_id: null,
        active_event_count: 0
      }));
      setNotice('Returned to demo monitoring feed');
      await fetchDashboardData();
    } catch (error) {
      setNotice('Could not clear SOC replay mode');
    } finally {
      setSocLoading(false);
      window.setTimeout(() => setNotice(''), 2600);
    }
  };

  const chooseSection = (section) => {
    setActiveSection(section.id);
    const firstMatch = section.categories
      ? feed.signals.find((signal) => section.categories.includes(signal.category))
      : feed.signals[0];
    if (firstMatch) {
      setSelectedId(firstMatch.id);
    }
    setNotice(`${section.label}: раздел открыт`);
    window.setTimeout(() => setNotice(''), 1800);
  };

  const chooseMode = (mode) => {
    setDefenseMode(mode.toLowerCase());
    setNotice(`${mode}: режим защиты переключен`);
    window.setTimeout(() => setNotice(''), 1800);
  };

  if (loading && !feed) {
    return <LoadingScreen />;
  }

  return (
    <div className="min-h-screen bg-[#071014] text-slate-100">
      <div className="grid min-h-screen grid-cols-1 xl:grid-cols-[280px_1fr]">
        <aside className="border-b border-slate-800 bg-slate-950/70 p-5 xl:border-b-0 xl:border-r">
          <div className="flex items-center gap-3">
            <div className="grid h-11 w-11 place-items-center rounded-lg border border-cyan-300/40 bg-cyan-300/10 text-cyan-200">
              <ShieldAlert className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-lg font-black leading-tight">AI Shield Guardian</h1>
              <p className="text-xs text-slate-400">Real-time cyber defense</p>
            </div>
          </div>

          <div className="mt-6 rounded-lg border border-amber-300/30 bg-amber-300/10 p-4">
            <div className="flex items-center gap-2 text-sm font-bold text-amber-100">
              <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-amber-300 shadow-[0_0_18px_rgba(252,211,77,.8)]" />
              {feed.risk_level} ATTENTION
            </div>
            <p className="mt-2 text-sm leading-5 text-slate-300">
              AI correlates access, user behavior, DLP, email, network, and endpoint signals.
            </p>
          </div>

          <nav className="mt-6 grid gap-2">
            {tabDefinitions.map(({ id, label, count, icon: Icon }) => (
              <button
                key={label}
                onClick={() => setActiveTab(id)}
                className={cx(
                  'flex h-11 items-center justify-between rounded-lg border px-3 text-left text-sm transition',
                  activeTab === id
                    ? 'border-cyan-300/30 bg-cyan-300/10 text-cyan-100'
                    : 'border-transparent text-slate-400 hover:border-slate-700 hover:bg-slate-900'
                )}
              >
                <span className="flex items-center gap-2">
                  <Icon className="h-4 w-4" />
                  {section.label}
                </span>
                <span className="rounded-full bg-red-400/15 px-2 py-0.5 text-xs text-red-100">
                  {section.id === 'response' ? actionLog.length : sectionCounts[section.id]}
                </span>
              </button>
              );
            })}
          </nav>
        </aside>

        <main className="min-w-0 p-4 lg:p-6">
          <header className="mb-5 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="flex items-center gap-2 text-sm font-semibold text-cyan-200">
                <Sparkles className="h-4 w-4" />
                Explainable AI security operations
              </p>
              <h2 className="mt-1 text-3xl font-black">{activeTabMeta.title}</h2>
              <p className="mt-1 text-sm text-slate-400">
                {activeTabMeta.description}
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {['Observe', 'Defend', 'Contain'].map((modeLabel) => (
                <button
                  key={modeLabel}
                  onClick={() => setSelectedMode(modeLabel.toLowerCase())}
                  className={cx(
                    'h-10 rounded-lg border px-4 text-sm font-semibold',
                    modeLabel.toLowerCase() === selectedMode
                      ? 'border-cyan-300 bg-cyan-300 text-slate-950'
                      : 'border-slate-700 bg-slate-900 text-slate-300'
                  )}
                >
                  {modeLabel}
                </button>
              ))}
              <button
                className="flex h-10 items-center gap-2 rounded-lg border border-cyan-300 bg-cyan-300 px-3 text-sm font-bold text-slate-950 disabled:cursor-not-allowed disabled:opacity-70"
                onClick={loadSocDataset}
                disabled={socLoading}
                title="Load downloaded OTRF SOC logs"
              >
                <Database className="h-4 w-4" />
                {socLoading ? 'Loading' : 'Load SOC'}
              </button>
              {socInfo?.active_event_count > 0 && (
                <button
                  className="h-10 rounded-lg border border-slate-700 bg-slate-900 px-3 text-sm font-semibold text-slate-200"
                  onClick={clearSocDataset}
                  disabled={socLoading}
                >
                  Demo data
                </button>
              )}
              <button
                className="grid h-10 w-10 place-items-center rounded-lg border border-slate-700 bg-slate-900 text-slate-200"
                onClick={fetchDashboardData}
                title="Refresh"
              >
                <RefreshCw className="h-4 w-4" />
              </button>
            </div>
          </header>

          <section className="mb-5 grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-4">
            <StatCard
              label="AI Risk Score"
              value={feed.overall_risk}
              note={`${feed.active_incidents} active incidents require review`}
              icon={AlertTriangle}
              tone="text-red-200"
            />
            <StatCard
              label="Mean Detect Time"
              value={`${feed.mean_detect_time_seconds}s`}
              note="from signal to explanation"
              icon={Clock3}
              tone="text-cyan-200"
            />
            <StatCard
              label="Blocked Data"
              value={`${feed.blocked_data_gb}GB`}
              note="sensitive export stopped by DLP"
              icon={Database}
              tone="text-amber-100"
            />
            <StatCard
              label="Protected Assets"
              value={feed.protected_assets}
              note="users, endpoints, APIs, mailboxes"
              icon={Shield}
              tone="text-emerald-200"
            />
          </section>

          {socInfo?.active_event_count > 0 && (
            <section className="mb-5 rounded-lg border border-cyan-300/30 bg-cyan-300/10 p-4">
              <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                <div>
                  <p className="text-sm font-bold text-cyan-100">OTRF SOC replay mode</p>
                  <p className="mt-1 text-sm text-slate-300">
                    {socInfo.active_event_count} normalized Windows security events are driving the dashboard feed.
                  </p>
                </div>
                <span className="rounded-full border border-cyan-300/40 px-3 py-1 text-xs font-bold text-cyan-100">
                  {feed.dataset_source || 'Security-Datasets'}
                </span>
              </div>
            </section>
          )}

          {activeTab === 'threat' && (
          <section className="grid grid-cols-1 gap-5 2xl:grid-cols-[1.25fr_.75fr]">
            <div className="grid gap-5">
              <div className="rounded-lg border border-slate-700/80 bg-slate-900/72 p-4 shadow-xl shadow-black/20">
                <div className="mb-4 flex items-center justify-between gap-3">
                  <div>
                    <h3 className="font-bold">Live Signal Correlation</h3>
                    <p className="text-sm text-slate-400">IAM, DLP, email, endpoint, and network telemetry</p>
                  </div>
                  <span className="rounded-full border border-red-400/40 bg-red-400/10 px-3 py-1 text-xs font-bold text-red-100">
                    Active incident
                  </span>
                </div>

                <div className="grid gap-4 lg:grid-cols-[1fr_260px]">
                  <div className="relative min-h-[310px] overflow-hidden rounded-lg border border-slate-800 bg-[linear-gradient(rgba(255,255,255,.04)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,.04)_1px,transparent_1px)] bg-[size:32px_32px]">
                    <div className="absolute left-1/2 top-1/2 h-64 w-64 -translate-x-1/2 -translate-y-1/2 rounded-full border border-cyan-300/30 bg-cyan-300/5">
                      <div className="absolute left-1/2 top-1/2 h-px w-32 origin-left animate-[spin_4.8s_linear_infinite] bg-gradient-to-r from-cyan-300 to-transparent" />
                    </div>
                    {[
                      ['left-[18%] top-[30%] bg-red-400', 'Access anomaly'],
                      ['left-[68%] top-[22%] bg-amber-300', 'Phishing source'],
                      ['left-[78%] top-[64%] bg-red-400', 'DLP hit'],
                      ['left-[44%] top-[70%] bg-cyan-300', 'Endpoint trace'],
                      ['left-[33%] top-[55%] bg-emerald-300', 'Normal baseline']
                    ].map(([position, label]) => (
                      <div key={label} className={cx('absolute h-3.5 w-3.5 rounded-full shadow-[0_0_22px_currentColor]', position)} title={label} />
                    ))}
                    <div className="absolute bottom-3 left-3 right-3 grid gap-2 md:grid-cols-2">
                      {feed.coverage.slice(0, 4).map((item) => (
                        <div key={item.name} className="rounded-lg border border-slate-700/70 bg-slate-950/80 p-3">
                          <p className="text-sm font-semibold">{item.name}</p>
                          <div className="mt-2 h-2 rounded-full bg-slate-800">
                            <div className="h-2 rounded-full bg-cyan-300" style={{ width: `${item.value}%` }} />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                    <h4 className="flex items-center gap-2 text-sm font-bold">
                      <BrainCircuit className="h-4 w-4 text-cyan-200" />
                      AI coverage
                    </h4>
                    <div className="mt-3 h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={feed.coverage} layout="vertical" margin={{ left: 18, right: 8, top: 4, bottom: 4 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                          <XAxis type="number" hide domain={[0, 100]} />
                          <YAxis type="category" dataKey="name" width={92} tick={{ fill: '#94a3b8', fontSize: 11 }} />
                          <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155' }} />
                          <Bar dataKey="value" fill="#67e8f9" radius={[0, 6, 6, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
                <div className="rounded-lg border border-slate-700/80 bg-slate-900/72 p-4 shadow-xl shadow-black/20">
                  <h3 className="mb-1 font-bold">AI Risk Timeline</h3>
                  <p className="mb-3 text-sm text-slate-400">Risk and confidence update every few seconds</p>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={chartData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                        <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 11 }} />
                        <YAxis stroke="#94a3b8" domain={[0, 100]} />
                        <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155' }} />
                        <Area type="monotone" dataKey="risk" stroke="#f87171" fill="#ef444433" name="Risk" />
                        <Area type="monotone" dataKey="confidence" stroke="#67e8f9" fill="#22d3ee22" name="Confidence" />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="rounded-lg border border-slate-700/80 bg-slate-900/72 p-4 shadow-xl shadow-black/20">
                  <h3 className="mb-1 font-bold">Response Timeline</h3>
                  <p className="mb-3 text-sm text-slate-400">Automated actions and analyst-ready evidence</p>
                  <div className="grid gap-3">
                    {feed.timeline.map((item) => (
                      <div key={`${item.time}-${item.event}`} className="grid grid-cols-[76px_1fr] gap-3 text-sm">
                        <span className="text-cyan-200">{item.time}</span>
                        <span className="text-slate-300">{item.event}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            <aside className="grid gap-5">
              <div className="rounded-lg border border-slate-700/80 bg-slate-900/72 p-4 shadow-xl shadow-black/20">
                <div className="mb-3 flex items-center justify-between">
                  <div>
                    <h3 className="font-bold">Recent Threats</h3>
                    <p className="text-sm text-slate-400">Click an incident to explain</p>
                  </div>
                  <Radar className="h-5 w-5 text-cyan-200" />
                </div>

                <div className="grid gap-3">
                  {activeSection === 'response' && actionLog.length > 0 && (
                    <div className="rounded-lg border border-emerald-300/30 bg-emerald-300/10 p-3">
                      <p className="text-sm font-bold text-emerald-100">Playbook actions</p>
                      <div className="mt-2 grid gap-2">
                        {actionLog.map((entry) => (
                          <p key={`${entry.time}-${entry.action}`} className="text-xs text-slate-300">
                            {entry.time} · {entry.action} · {entry.incident} · {entry.mode.toUpperCase()}
                          </p>
                        ))}
                      </div>
                    </div>
                  )}

                  {visibleSignals.map((signal) => {
                    const Icon = categoryIcons[signal.category] || Eye;
                    return (
                      <button
                        key={signal.id}
                        onClick={() => setSelectedId(signal.id)}
                        className={cx(
                          'rounded-lg border p-3 text-left transition',
                          selectedSignal.id === signal.id
                            ? 'border-cyan-300/50 bg-cyan-300/10'
                            : 'border-slate-800 bg-slate-950/40 hover:border-slate-600'
                        )}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex gap-3">
                            <div className="grid h-9 w-9 place-items-center rounded-lg border border-slate-700 bg-slate-900 text-cyan-200">
                              <Icon className="h-4 w-4" />
                            </div>
                            <div>
                              <p className="font-semibold">{signal.title}</p>
                              <p className="mt-1 text-xs text-slate-400">{signal.source}</p>
                            </div>
                          </div>
                          <span className={cx('rounded-full border px-2 py-1 text-xs font-bold', severityClass[signal.severity])}>
                            {signal.risk_score}
                          </span>
                        </div>
                      </button>
                    );
                  })}

                  {visibleSignals.length === 0 && (
                    <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-4 text-sm text-slate-400">
                      No incidents in this section yet. The device telemetry is still being monitored.
                    </div>
                  )}
                </div>
              </div>

              <div className="rounded-lg border border-slate-700/80 bg-slate-900/72 p-4 shadow-xl shadow-black/20">
                <div className="mb-4 flex items-start justify-between gap-3">
                  <div>
                    <h3 className="font-bold">AI Decision</h3>
                    <p className="text-sm text-slate-400">{selectedSignal.id} / {selectedSignal.category}</p>
                  </div>
                  <span className={cx('rounded-full border px-3 py-1 text-xs font-bold', severityClass[selectedSignal.severity])}>
                    {selectedSignal.confidence}% confidence
                  </span>
                </div>

                <h4 className="text-xl font-black text-red-100">{selectedSignal.title}</h4>
                <p className="mt-2 text-sm leading-6 text-slate-300">{selectedSignal.summary}</p>

                <div className="mt-4 grid gap-3">
                  {selectedSignal.factors.map((factor) => (
                    <div key={factor.name}>
                      <div className="mb-1 flex justify-between text-xs text-slate-400">
                        <span>{factor.name}</span>
                        <span>{factor.weight}%</span>
                      </div>
                      <div className="h-2 rounded-full bg-slate-800">
                        <div
                          className="h-2 rounded-full bg-gradient-to-r from-cyan-300 via-amber-300 to-red-400"
                          style={{ width: `${factor.weight}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>

                <div className="mt-4 border-t border-slate-800 pt-4">
                  <p className="mb-2 text-sm font-bold">Evidence</p>
                  <div className="grid gap-2">
                    {selectedSignal.evidence.map((item) => (
                      <p key={item} className="flex gap-2 text-sm leading-5 text-slate-300">
                        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
                        {item}
                      </p>
                    ))}
                  </div>
                </div>

                <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-3">
                  {selectedSignal.recommended_actions.map((action, index) => (
                    <button
                      key={action}
                      onClick={() => runAction(action)}
                      className={cx(
                        'min-h-10 rounded-lg border px-3 text-sm font-bold',
                        index === 0
                          ? 'border-cyan-300 bg-cyan-300 text-slate-950'
                          : 'border-slate-700 bg-slate-950 text-slate-200 hover:border-cyan-300/50'
                      )}
                    >
                      {action}
                    </button>
                  ))}
                </div>
              </div>

              <div className="rounded-lg border border-slate-700/80 bg-slate-900/72 p-4 shadow-xl shadow-black/20">
                <h3 className="mb-3 font-bold">Device Analysis Context</h3>
                <div className="grid grid-cols-2 gap-3">
                  <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                    <p className="text-xs text-slate-400">CPU</p>
                    <p className="mt-1 text-xl font-black">{feed.device_context?.cpu_percent?.toFixed?.(1) || status?.cpu_percent?.toFixed(1) || '0.0'}%</p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                    <p className="text-xs text-slate-400">Memory</p>
                    <p className="mt-1 text-xl font-black">{feed.device_context?.memory_percent?.toFixed?.(1) || status?.memory_percent?.toFixed(1) || '0.0'}%</p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                    <p className="text-xs text-slate-400">Processes</p>
                    <p className="mt-1 text-xl font-black">{feed.device_context?.active_processes || status?.active_processes || 0}</p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                    <p className="text-xs text-slate-400">Connections</p>
                    <p className="mt-1 text-xl font-black">{feed.device_context?.network_connections || status?.network_connections || 0}</p>
                  </div>
                </div>

                <div className="mt-4 border-t border-slate-800 pt-4">
                  <p className="mb-2 text-sm font-bold">Top device processes</p>
                  <div className="grid gap-2">
                    {(feed.device_context?.process_watchlist || []).slice(0, 4).map((proc) => (
                      <div key={`${proc.pid}-${proc.name}`} className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
                        <div className="flex items-center justify-between gap-3">
                          <p className="truncate text-sm font-semibold">{proc.name}</p>
                          <span className="text-xs text-slate-400">PID {proc.pid}</span>
                        </div>
                        <p className="mt-1 text-xs text-slate-400">
                          CPU {proc.cpu_percent}% · RAM {proc.memory_gb}GB
                        </p>
                      </div>
                    ))}
                    {(feed.device_context?.process_watchlist || []).length === 0 && (
                      <p className="text-sm text-slate-400">Waiting for live process telemetry...</p>
                    )}
                  </div>
                </div>

                <div className="mt-4 border-t border-slate-800 pt-4">
                  <p className="mb-2 text-sm font-bold">Analysis basis</p>
                  <div className="grid gap-2">
                    {(feed.device_context?.analysis_basis || []).map((item) => (
                      <p key={item} className="flex gap-2 text-xs leading-5 text-slate-400">
                        <Eye className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan-200" />
                        {item}
                      </p>
                    ))}
                  </div>
                </div>
              </div>
            </aside>
          </section>
          )}

          {activeTab === 'access' && (
            <AccessTab
              signals={accessSignals}
              processes={processes}
              status={status}
              selectedId={selectedId}
              onSelect={setSelectedId}
              onAction={runAction}
            />
          )}

          {activeTab === 'dlp' && (
            <DlpTab
              signals={dlpSignals}
              feed={feed}
              selectedId={selectedId}
              onSelect={setSelectedId}
              onAction={runAction}
            />
          )}

          {activeTab === 'phishing' && (
            <PhishingTab
              signals={phishingSignals}
              connections={connections}
              selectedId={selectedId}
              onSelect={setSelectedId}
              onAction={runAction}
            />
          )}

          {activeTab === 'response' && (
            <ResponseTab
              selectedSignal={selectedSignal}
              analysis={analysis}
              analysisActions={analysisActions}
              actionLog={actionLog}
              socEvents={socEvents}
              analyzing={analyzing}
              onAnalyze={runFullAnalysis}
              onAction={runAction}
            />
          )}
        </main>
      </div>

      {notice && (
        <div className="fixed bottom-5 right-5 max-w-sm rounded-lg border border-cyan-300/40 bg-slate-950 px-4 py-3 text-sm shadow-2xl shadow-black/40">
          <div className="flex gap-2">
            <Zap className="h-4 w-4 shrink-0 text-cyan-200" />
            <span>{notice}</span>
          </div>
        </div>
      )}
    </div>
  );
}
