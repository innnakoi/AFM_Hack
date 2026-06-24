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
  Database,
  Eye,
  FileWarning,
  Fingerprint,
  Lock,
  MailWarning,
  Radar,
  RefreshCw,
  Shield,
  ShieldAlert,
  Siren,
  Sparkles,
  TerminalSquare,
  UserX,
  Zap
} from 'lucide-react';
import axios from 'axios';

const API_BASE = 'http://127.0.0.1:8000/api';

const fallbackFeed = {
  mode: 'defend',
  overall_risk: 89,
  risk_level: 'HIGH',
  mean_detect_time_seconds: 0.9,
  blocked_data_gb: 1.7,
  protected_assets: 1248,
  active_incidents: 3,
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
  const [chartData, setChartData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState('');

  const selectedSignal = useMemo(() => {
    return feed.signals.find((signal) => signal.id === selectedId) || feed.signals[0];
  }, [feed, selectedId]);

  const fetchDashboardData = useCallback(async () => {
    try {
      const [statusRes, feedRes] = await Promise.all([
        axios.get(`${API_BASE}/status`),
        axios.get(`${API_BASE}/security-feed`)
      ]);

      setStatus(statusRes.data);
      setFeed(feedRes.data);
      setSelectedId((current) => {
        const exists = feedRes.data.signals.some((signal) => signal.id === current);
        return exists ? current : feedRes.data.signals[0]?.id;
      });
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
    setNotice(`${action}: команда добавлена в playbook реагирования`);
    window.setTimeout(() => setNotice(''), 2600);
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
            {[
              ['Threat Center', feed.active_incidents, Siren],
              ['Access AI', 2, Fingerprint],
              ['DLP Control', 1, FileWarning],
              ['Phishing Lab', 3, MailWarning],
              ['Response', 5, Lock]
            ].map(([label, count, Icon], index) => (
              <button
                key={label}
                className={cx(
                  'flex h-11 items-center justify-between rounded-lg border px-3 text-left text-sm transition',
                  index === 0
                    ? 'border-cyan-300/30 bg-cyan-300/10 text-cyan-100'
                    : 'border-transparent text-slate-400 hover:border-slate-700 hover:bg-slate-900'
                )}
              >
                <span className="flex items-center gap-2">
                  <Icon className="h-4 w-4" />
                  {label}
                </span>
                <span className="rounded-full bg-red-400/15 px-2 py-0.5 text-xs text-red-100">{count}</span>
              </button>
            ))}
          </nav>
        </aside>

        <main className="min-w-0 p-4 lg:p-6">
          <header className="mb-5 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="flex items-center gap-2 text-sm font-semibold text-cyan-200">
                <Sparkles className="h-4 w-4" />
                Explainable AI security operations
              </p>
              <h2 className="mt-1 text-3xl font-black">Threat Detection & Response</h2>
              <p className="mt-1 text-sm text-slate-400">
                Detects unauthorized access, abnormal users, data leaks, phishing, and compromise indicators in real time.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {['Observe', 'Defend', 'Contain'].map((mode) => (
                <button
                  key={mode}
                  className={cx(
                    'h-10 rounded-lg border px-4 text-sm font-semibold',
                    mode.toLowerCase() === feed.mode
                      ? 'border-cyan-300 bg-cyan-300 text-slate-950'
                      : 'border-slate-700 bg-slate-900 text-slate-300'
                  )}
                >
                  {mode}
                </button>
              ))}
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
                  {feed.signals.map((signal) => {
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
                <h3 className="mb-3 font-bold">System Context</h3>
                <div className="grid grid-cols-2 gap-3">
                  <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                    <p className="text-xs text-slate-400">CPU</p>
                    <p className="mt-1 text-xl font-black">{status?.cpu_percent?.toFixed(1) || '0.0'}%</p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                    <p className="text-xs text-slate-400">Memory</p>
                    <p className="mt-1 text-xl font-black">{status?.memory_percent?.toFixed(1) || '0.0'}%</p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                    <p className="text-xs text-slate-400">Processes</p>
                    <p className="mt-1 text-xl font-black">{status?.active_processes || 0}</p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                    <p className="text-xs text-slate-400">Connections</p>
                    <p className="mt-1 text-xl font-black">{status?.network_connections || 0}</p>
                  </div>
                </div>
              </div>
            </aside>
          </section>
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
