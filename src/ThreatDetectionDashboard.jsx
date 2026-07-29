import React, { useState, useEffect, useRef, useMemo } from "react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";
import {
  Shield, ShieldAlert, ShieldCheck, Radio, Activity, AlertTriangle, ChevronRight,
  X, Filter, Terminal, Crosshair, CheckCircle2, Circle, Pause, Play,
} from "lucide-react";

// ---------------------------------------------------------------------------
// Design tokens
// ---------------------------------------------------------------------------
const COLORS = {
  bg: "#0A0E17",
  panel: "#0F1522",
  panelAlt: "#131A29",
  border: "#1E2836",
  borderSoft: "#161E2C",
  text: "#DCE3ED",
  textMuted: "#647089",
  textFaint: "#3D4759",
  critical: "#FB4560",
  high: "#F2A93B",
  medium: "#3FA9F5",
  low: "#31C48D",
  info: "#7C8AAF",
};

const SEV_ORDER = ["critical", "high", "medium", "low"];
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

// ---------------------------------------------------------------------------
// MITRE ATT&CK-inspired scenario library
// ---------------------------------------------------------------------------
const SCENARIOS = [
  {
    tactic: "Credential Access", techniqueId: "T1110", technique: "Brute Force",
    title: "Repeated failed authentication attempts",
    detail: (ip) => `${ip} sent 47 failed SSH logins against host db-prod-02 in 90 seconds, cycling through a common-password wordlist.`,
    severity: "high", baseScore: 74,
    mitigations: [
      "Lock the targeted account and force a credential reset",
      "Block source IP at the perimeter firewall",
      "Enable adaptive lockout / rate limiting on the SSH bastion",
      "Verify no successful login occurred in the same window",
    ],
  },
  {
    tactic: "Reconnaissance", techniqueId: "T1595", technique: "Active Scanning",
    title: "Sequential port scan detected",
    detail: (ip) => `${ip} probed 1,200+ ports across the 10.0.4.0/24 subnet in under a minute — classic SYN scan fingerprint.`,
    severity: "medium", baseScore: 46,
    mitigations: [
      "Add source IP to the watchlist for 72 hours",
      "Confirm scan didn't originate from an authorized vuln-scan job",
      "Rate-limit inbound SYN packets on the edge router",
    ],
  },
  {
    tactic: "Execution", techniqueId: "T1059.001", technique: "PowerShell",
    title: "Obfuscated PowerShell execution",
    detail: (ip) => `Endpoint WKSTN-${ip.split(".").pop()} ran a base64-encoded PowerShell command spawned from winword.exe.`,
    severity: "critical", baseScore: 91,
    mitigations: [
      "Isolate the endpoint from the network immediately",
      "Capture memory image before remediation",
      "Decode and review the payload in a sandbox",
      "Hunt for related persistence mechanisms (T1547)",
    ],
  },
  {
    tactic: "Exfiltration", techniqueId: "T1041", technique: "Exfil Over C2 Channel",
    title: "Anomalous outbound data volume",
    detail: (ip) => `Host ${ip} pushed 2.3 GB to an unfamiliar external endpoint over HTTPS, 18x its 30-day baseline.`,
    severity: "critical", baseScore: 88,
    mitigations: [
      "Block outbound traffic to the destination IP/domain",
      "Snapshot the host for forensic review",
      "Identify what data left and notify data owner",
      "Check DLP logs for matching sensitive file access",
    ],
  },
  {
    tactic: "Persistence", techniqueId: "T1136.001", technique: "Local Account Creation",
    title: "New local administrator account",
    detail: (ip) => `A local admin account "svc_updater" was created on ${ip} outside the change-management window.`,
    severity: "high", baseScore: 69,
    mitigations: [
      "Disable the account pending investigation",
      "Confirm creation against approved change tickets",
      "Review the parent process that spawned the creation command",
    ],
  },
  {
    tactic: "Lateral Movement", techniqueId: "T1021.002", technique: "SMB/Windows Admin Shares",
    title: "Unusual SMB session fan-out",
    detail: (ip) => `${ip} opened admin$ sessions against 6 hosts within 40 seconds, none part of its normal access pattern.`,
    severity: "high", baseScore: 77,
    mitigations: [
      "Segment the source host from the rest of VLAN 40",
      "Rotate credentials used in the SMB sessions",
      "Review for PsExec or similar remote-execution tooling",
    ],
  },
  {
    tactic: "Command and Control", techniqueId: "T1071.004", technique: "DNS Tunneling",
    title: "High-entropy DNS query pattern",
    detail: (ip) => `${ip} generated 300+ DNS queries/min to a single parent domain with high Shannon entropy subdomains.`,
    severity: "medium", baseScore: 58,
    mitigations: [
      "Sinkhole the suspicious domain",
      "Inspect the resolver logs for the full query history",
      "Check the host for known tunneling utilities",
    ],
  },
  {
    tactic: "Discovery", techniqueId: "T1087", technique: "Account Discovery",
    title: "Bulk directory enumeration",
    detail: (ip) => `${ip} issued LDAP queries enumerating all domain user and group objects in a single session.`,
    severity: "low", baseScore: 33,
    mitigations: [
      "Confirm requestor identity and business justification",
      "Add query pattern to baseline if legitimate tooling",
    ],
  },
  {
    tactic: "Impact", techniqueId: "T1486", technique: "Data Encrypted for Impact",
    title: "Mass file modification burst",
    detail: (ip) => `${ip} rewrote 4,800 files with new extensions across two file shares in 3 minutes — ransomware-consistent behavior.`,
    severity: "critical", baseScore: 97,
    mitigations: [
      "Kill the offending process and isolate the host now",
      "Disconnect affected shares to stop the spread",
      "Trigger backup-restore procedure for impacted volumes",
      "Notify incident commander and begin IR playbook",
    ],
  },
  {
    tactic: "Initial Access", techniqueId: "T1078", technique: "Valid Accounts",
    title: "Impossible-travel login",
    detail: (ip) => `Account jsmith authenticated from ${ip} eleven minutes after a login from a location 6,200 miles away.`,
    severity: "high", baseScore: 81,
    mitigations: [
      "Force-expire the active session",
      "Require step-up MFA re-verification",
      "Contact user through a known-good channel to confirm",
    ],
  },
  {
    tactic: "Defense Evasion", techniqueId: "T1070.001", technique: "Clear Windows Event Logs",
    title: "Security event log cleared",
    detail: (ip) => `The Security event log on ${ip} was cleared 90 seconds after an interactive admin logon.`,
    severity: "critical", baseScore: 85,
    mitigations: [
      "Isolate host and preserve remaining logs immediately",
      "Pull logs from the SIEM's independent forwarder copy",
      "Identify the account that performed the logon",
    ],
  },
  {
    tactic: "Collection", techniqueId: "T1560", technique: "Archive Collected Data",
    title: "Staged archive in temp directory",
    detail: (ip) => `A 900MB password-protected .zip appeared in C:\\Windows\\Temp on ${ip}, built from files across 4 departments' shares.`,
    severity: "medium", baseScore: 62,
    mitigations: [
      "Quarantine the archive for analysis",
      "Trace which process wrote each source file into it",
      "Watch the host for a follow-on exfil attempt",
    ],
  },
];

const LOG_TEMPLATES = [
  (ip) => `sshd[${rnd(1000,9999)}]: Failed password for invalid user admin from ${ip} port ${rnd(1024,65000)} ssh2`,
  (ip) => `firewall: ACCEPT TCP ${ip}:${rnd(1024,65000)} -> 10.0.2.14:443 len=${rnd(60,1500)}`,
  (ip) => `dns: query A ${rnd(2,9)}x${Math.random().toString(36).slice(2,10)}.telemetry-sync.net from ${ip}`,
  (ip) => `edr: process svchost.exe (pid ${rnd(1000,50000)}) spawned by explorer.exe on host ${ip}`,
  (ip) => `auth: user jsmith authenticated successfully from ${ip} via SAML`,
  (ip) => `proxy: GET https://cdn-assets-${rnd(10,99)}.io/ok 200 ${rnd(200,900)}ms client=${ip}`,
  (ip) => `netflow: ${ip} -> 198.51.100.${rnd(2,254)} bytes=${rnd(1000,50000)} proto=TCP`,
  (ip) => `wineventlog: 4624 An account was successfully logged on host ${ip}`,
];

function rnd(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randIp() { return `${rnd(10,203)}.${rnd(0,255)}.${rnd(0,255)}.${rnd(1,254)}`; }
function fmtTime(d) {
  return d.toLocaleTimeString("en-US", { hour12: false });
}
function fmtClock(d) {
  return d.toLocaleTimeString("en-US", { hour12: false });
}

let idCounter = 1;
function nextId() { return idCounter++; }

// ---------------------------------------------------------------------------
// Risk gauge
// ---------------------------------------------------------------------------
function RiskGauge({ score }) {
  const pct = Math.max(0, Math.min(100, score));
  const angle = (pct / 100) * 180;
  const color = pct >= 75 ? COLORS.critical : pct >= 50 ? COLORS.high : pct >= 25 ? COLORS.medium : COLORS.low;
  const r = 54, cx = 64, cy = 64;
  const toRad = (deg) => (Math.PI * deg) / 180;
  const startAngle = 180;
  const endAngle = 180 - angle;
  const point = (deg) => [cx + r * Math.cos(toRad(deg)), cy - r * Math.sin(toRad(deg))];
  const [x1, y1] = point(startAngle);
  const [x2, y2] = point(endAngle);
  const largeArc = angle > 180 ? 1 : 0;

  return (
    <svg width="128" height="80" viewBox="0 0 128 80">
      <path
        d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
        fill="none" stroke={COLORS.border} strokeWidth="10" strokeLinecap="round"
      />
      <path
        d={`M ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2}`}
        fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
      />
      <text x={cx} y={cy - 4} textAnchor="middle" fontSize="26" fontWeight="600" fill={COLORS.text} fontFamily="'JetBrains Mono', monospace">
        {Math.round(pct)}
      </text>
      <text x={cx} y={cy + 14} textAnchor="middle" fontSize="9" fill={COLORS.textMuted} letterSpacing="1">
        RISK INDEX
      </text>
    </svg>
  );
}

// ---------------------------------------------------------------------------
// MITRE tactic heatmap
// ---------------------------------------------------------------------------
const TACTICS = [
  "Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact",
];

function MitreHeatmap({ counts, onSelectTactic, selectedTactic }) {
  const max = Math.max(1, ...Object.values(counts));
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 6 }}>
      {TACTICS.map((t) => {
        const c = counts[t] || 0;
        const intensity = c / max;
        const bg = c === 0
          ? COLORS.panelAlt
          : intensity > 0.66 ? "rgba(251,69,96,0.28)"
          : intensity > 0.33 ? "rgba(242,169,59,0.24)"
          : "rgba(63,169,245,0.20)";
        const border = c === 0 ? COLORS.borderSoft : (selectedTactic === t ? COLORS.text : "transparent");
        return (
          <button
            key={t}
            onClick={() => onSelectTactic(selectedTactic === t ? null : t)}
            style={{
              background: bg, border: `1px solid ${border}`, borderRadius: 6,
              padding: "8px 6px", textAlign: "left", cursor: "pointer",
              display: "flex", flexDirection: "column", gap: 4, minHeight: 52,
            }}
          >
            <span style={{ fontSize: 10, color: COLORS.textMuted, lineHeight: 1.2 }}>{t}</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 15, color: COLORS.text, fontWeight: 600 }}>{c}</span>
          </button>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export default function ThreatDetectionDashboard() {
  const [alerts, setAlerts] = useState([]);
  const [ticker, setTicker] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [sevFilter, setSevFilter] = useState("all");
  const [tacticFilter, setTacticFilter] = useState(null);
  const [running, setRunning] = useState(true);
  const [clock, setClock] = useState(new Date());
  const [eventsProcessed, setEventsProcessed] = useState(18422);
  const [timeline, setTimeline] = useState(() =>
    Array.from({ length: 16 }, (_, i) => ({
      t: i, label: "", critical: 0, high: 0, medium: 0, low: 0,
    }))
  );
  const [mitigatedIds, setMitigatedIds] = useState(new Set());
  const runningRef = useRef(running);
  runningRef.current = running;

  // Seed with a few historical alerts so the board doesn't start empty
  useEffect(() => {
    const seed = [];
    const now = Date.now();
    for (let i = 0; i < 6; i++) {
      const s = SCENARIOS[rnd(0, SCENARIOS.length - 1)];
      const ip = randIp();
      const t = new Date(now - rnd(30, 900) * 1000);
      seed.push({
        id: nextId(), time: t, ip, severity: s.severity,
        score: s.baseScore + rnd(-4, 4), tactic: s.tactic,
        techniqueId: s.techniqueId, technique: s.technique,
        title: s.title, description: s.detail(ip),
        mitigations: s.mitigations, status: i === 0 ? "investigating" : "new",
      });
    }
    seed.sort((a, b) => b.time - a.time);
    setAlerts(seed);
  }, []);

  // Clock
  useEffect(() => {
    const id = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  // Log ticker
  useEffect(() => {
    const id = setInterval(() => {
      if (!runningRef.current) return;
      const ip = randIp();
      const line = LOG_TEMPLATES[rnd(0, LOG_TEMPLATES.length - 1)](ip);
      setTicker((prev) => [{ id: nextId(), text: line, time: new Date() }, ...prev].slice(0, 40));
      setEventsProcessed((prev) => prev + rnd(3, 11));
    }, 1400);
    return () => clearInterval(id);
  }, []);

  // Alert generator
  useEffect(() => {
    let cancelled = false;
    function scheduleNext() {
      const delay = rnd(4000, 8500);
      const id = setTimeout(() => {
        if (!cancelled && runningRef.current) {
          const s = SCENARIOS[rnd(0, SCENARIOS.length - 1)];
          const ip = randIp();
          const alert = {
            id: nextId(), time: new Date(), ip, severity: s.severity,
            score: Math.min(99, Math.max(5, s.baseScore + rnd(-6, 6))),
            tactic: s.tactic, techniqueId: s.techniqueId, technique: s.technique,
            title: s.title, description: s.detail(ip),
            mitigations: s.mitigations, status: "new",
          };
          setAlerts((prev) => [alert, ...prev].slice(0, 60));
        }
        if (!cancelled) scheduleNext();
      }, delay);
      return id;
    }
    const t = scheduleNext();
    return () => { cancelled = true; clearTimeout(t); };
  }, []);

  // Timeline bucket update whenever alerts change
  useEffect(() => {
    setTimeline((prev) => {
      const next = [...prev];
      const last = { ...next[next.length - 1] };
      const bucket = { critical: 0, high: 0, medium: 0, low: 0 };
      const cutoff = Date.now() - 45000;
      alerts.forEach((a) => {
        if (a.time.getTime() >= cutoff) bucket[a.severity]++;
      });
      next[next.length - 1] = { ...last, ...bucket, label: fmtClock(new Date()) };
      return next;
    });
  }, [alerts]);

  // Roll timeline buckets forward every 15s
  useEffect(() => {
    const id = setInterval(() => {
      setTimeline((prev) => {
        const next = prev.slice(1);
        next.push({ t: prev[prev.length - 1].t + 1, label: fmtClock(new Date()), critical: 0, high: 0, medium: 0, low: 0 });
        return next;
      });
    }, 15000);
    return () => clearInterval(id);
  }, []);

  const mitreCounts = useMemo(() => {
    const counts = {};
    alerts.forEach((a) => { counts[a.tactic] = (counts[a.tactic] || 0) + 1; });
    return counts;
  }, [alerts]);

  const overallRisk = useMemo(() => {
    if (alerts.length === 0) return 12;
    const weights = { critical: 1, high: 0.7, medium: 0.4, low: 0.2 };
    const recent = alerts.slice(0, 12);
    const sum = recent.reduce((acc, a) => acc + a.score * weights[a.severity], 0);
    return Math.min(99, sum / recent.length);
  }, [alerts]);

  const filtered = alerts.filter((a) => {
    if (sevFilter !== "all" && a.severity !== sevFilter) return false;
    if (tacticFilter && a.tactic !== tacticFilter) return false;
    return true;
  });

  const selected = alerts.find((a) => a.id === selectedId) || null;
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  alerts.forEach((a) => counts[a.severity]++);

  function toggleMitigation(alertId, idx) {
    const key = `${alertId}:${idx}`;
    setMitigatedIds((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  return (
    <div style={{
      fontFamily: "'Inter', system-ui, sans-serif", background: COLORS.bg, color: COLORS.text,
      minHeight: "100vh", padding: "20px 24px 40px",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-thumb { background: ${COLORS.border}; border-radius: 3px; }
        button { font-family: inherit; }
        @keyframes pulse-dot { 0%,100% { opacity: 1; } 50% { opacity: 0.35; } }
      `}</style>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 18, flexWrap: "wrap", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Shield size={22} color={COLORS.medium} strokeWidth={1.8} />
          <div>
            <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 600, fontSize: 18, letterSpacing: 0.3 }}>
              SENTINEL <span style={{ color: COLORS.textMuted, fontWeight: 500 }}>// threat detection agent</span>
            </div>
            <div style={{ fontSize: 11, color: COLORS.textMuted, display: "flex", alignItems: "center", gap: 6, marginTop: 2 }}>
              <span style={{
                width: 6, height: 6, borderRadius: 99, background: running ? COLORS.low : COLORS.textFaint,
                display: "inline-block", animation: running ? "pulse-dot 1.6s infinite" : "none",
              }} />
              {running ? "Monitoring active" : "Monitoring paused"} · {eventsProcessed.toLocaleString()} events processed
            </div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: COLORS.textMuted }}>
            {fmtClock(clock)}
          </div>
          <button
            onClick={() => setRunning((r) => !r)}
            style={{
              display: "flex", alignItems: "center", gap: 6, background: COLORS.panel,
              border: `1px solid ${COLORS.border}`, color: COLORS.text, borderRadius: 7,
              padding: "7px 12px", fontSize: 12.5, cursor: "pointer",
            }}
          >
            {running ? <Pause size={13} /> : <Play size={13} />}
            {running ? "Pause feed" : "Resume feed"}
          </button>
        </div>
      </div>

      {/* Live log ticker */}
      <div style={{
        background: COLORS.panel, border: `1px solid ${COLORS.border}`, borderRadius: 8,
        padding: "8px 14px", marginBottom: 18, display: "flex", alignItems: "center", gap: 10,
        overflow: "hidden", height: 34,
      }}>
        <Terminal size={14} color={COLORS.textFaint} style={{ flexShrink: 0 }} />
        <div style={{
          fontFamily: "'JetBrains Mono', monospace", fontSize: 11.5, color: COLORS.textMuted,
          whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", flex: 1,
        }}>
          {ticker.length === 0 ? "Waiting for log stream…" : ticker.slice(0, 6).map((l) => l.text).join("    ·    ")}
        </div>
      </div>

      {/* Stat strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, marginBottom: 18 }}>
        {SEV_ORDER.map((sev) => (
          <div key={sev} style={{
            background: COLORS.panel, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: "12px 14px",
            borderLeft: `3px solid ${COLORS[sev]}`,
          }}>
            <div style={{ fontSize: 11, color: COLORS.textMuted, marginBottom: 4 }}>{SEV_LABEL[sev]} alerts</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 22, fontWeight: 600 }}>{counts[sev]}</div>
          </div>
        ))}
      </div>

      {/* Main grid */}
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1.4fr) minmax(0, 1fr)", gap: 16 }}>

        {/* Alert stream */}
        <div style={{ background: COLORS.panel, border: `1px solid ${COLORS.border}`, borderRadius: 10, display: "flex", flexDirection: "column", minHeight: 420 }}>
          <div style={{ padding: "14px 16px", borderBottom: `1px solid ${COLORS.borderSoft}`, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 600, fontSize: 14 }}>
              <ShieldAlert size={16} color={COLORS.high} /> Alert stream
            </div>
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <Filter size={12} color={COLORS.textMuted} />
              {["all", ...SEV_ORDER].map((s) => (
                <button
                  key={s}
                  onClick={() => setSevFilter(s)}
                  style={{
                    fontSize: 11, padding: "4px 9px", borderRadius: 99, cursor: "pointer",
                    border: `1px solid ${sevFilter === s ? COLORS.text : COLORS.border}`,
                    background: sevFilter === s ? COLORS.panelAlt : "transparent",
                    color: sevFilter === s ? COLORS.text : COLORS.textMuted,
                  }}
                >
                  {s === "all" ? "All" : SEV_LABEL[s]}
                </button>
              ))}
            </div>
          </div>
          {tacticFilter && (
            <div style={{ padding: "8px 16px", fontSize: 11.5, color: COLORS.textMuted, display: "flex", alignItems: "center", gap: 6, borderBottom: `1px solid ${COLORS.borderSoft}` }}>
              Filtered by tactic: <span style={{ color: COLORS.text }}>{tacticFilter}</span>
              <button onClick={() => setTacticFilter(null)} style={{ background: "none", border: "none", color: COLORS.textMuted, cursor: "pointer", display: "flex" }}><X size={12} /></button>
            </div>
          )}
          <div style={{ overflowY: "auto", maxHeight: 480 }}>
            {filtered.length === 0 && (
              <div style={{ padding: 24, color: COLORS.textMuted, fontSize: 13 }}>No alerts match this filter.</div>
            )}
            {filtered.map((a) => (
              <button
                key={a.id}
                onClick={() => setSelectedId(a.id)}
                style={{
                  width: "100%", textAlign: "left", background: selectedId === a.id ? COLORS.panelAlt : "transparent",
                  border: "none", borderBottom: `1px solid ${COLORS.borderSoft}`, padding: "11px 16px",
                  cursor: "pointer", display: "flex", alignItems: "center", gap: 10,
                }}
              >
                <span style={{ width: 8, height: 8, borderRadius: 99, background: COLORS[a.severity], flexShrink: 0 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 500, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{a.title}</div>
                  <div style={{ fontSize: 11, color: COLORS.textMuted, display: "flex", gap: 8, marginTop: 2 }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace" }}>{a.techniqueId}</span>
                    <span>{a.tactic}</span>
                    <span>{fmtTime(a.time)}</span>
                  </div>
                </div>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: COLORS[a.severity], fontWeight: 600 }}>{Math.round(a.score)}</div>
                <ChevronRight size={14} color={COLORS.textFaint} />
              </button>
            ))}
          </div>
        </div>

        {/* Right column */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

          {/* Risk + timeline */}
          <div style={{ background: COLORS.panel, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 16 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
              <RiskGauge score={overallRisk} />
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 12, color: COLORS.textMuted, marginBottom: 6, display: "flex", alignItems: "center", gap: 6 }}>
                  <Activity size={12} /> Alert volume, last window
                </div>
                <div style={{ height: 70 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timeline}>
                      <defs>
                        <linearGradient id="crit" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor={COLORS.critical} stopOpacity={0.5} />
                          <stop offset="100%" stopColor={COLORS.critical} stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="t" hide />
                      <YAxis hide />
                      <Tooltip
                        contentStyle={{ background: COLORS.panelAlt, border: `1px solid ${COLORS.border}`, borderRadius: 6, fontSize: 11 }}
                        labelFormatter={() => ""}
                      />
                      <Area type="monotone" dataKey="critical" stackId="1" stroke={COLORS.critical} fill={COLORS.critical} fillOpacity={0.35} />
                      <Area type="monotone" dataKey="high" stackId="1" stroke={COLORS.high} fill={COLORS.high} fillOpacity={0.3} />
                      <Area type="monotone" dataKey="medium" stackId="1" stroke={COLORS.medium} fill={COLORS.medium} fillOpacity={0.25} />
                      <Area type="monotone" dataKey="low" stackId="1" stroke={COLORS.low} fill={COLORS.low} fillOpacity={0.2} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          </div>

          {/* MITRE heatmap */}
          <div style={{ background: COLORS.panel, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 16 }}>
            <div style={{ fontSize: 12, color: COLORS.textMuted, marginBottom: 10, display: "flex", alignItems: "center", gap: 6 }}>
              <Crosshair size={12} /> MITRE ATT&CK tactic coverage
            </div>
            <MitreHeatmap counts={mitreCounts} onSelectTactic={setTacticFilter} selectedTactic={tacticFilter} />
          </div>
        </div>
      </div>

      {/* Detail drawer */}
      {selected && (
        <div style={{
          position: "fixed", top: 0, right: 0, bottom: 0, width: 380, maxWidth: "92vw",
          background: COLORS.panel, borderLeft: `1px solid ${COLORS.border}`, boxShadow: "-8px 0 30px rgba(0,0,0,0.4)",
          padding: 20, overflowY: "auto", zIndex: 50,
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ width: 9, height: 9, borderRadius: 99, background: COLORS[selected.severity] }} />
              <span style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 0.5, color: COLORS[selected.severity], fontWeight: 600 }}>
                {SEV_LABEL[selected.severity]} · risk {Math.round(selected.score)}
              </span>
            </div>
            <button onClick={() => setSelectedId(null)} style={{ background: "none", border: "none", color: COLORS.textMuted, cursor: "pointer" }}>
              <X size={16} />
            </button>
          </div>

          <div style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: 17, fontWeight: 600, marginBottom: 8 }}>
            {selected.title}
          </div>
          <div style={{ fontSize: 13, color: COLORS.textMuted, lineHeight: 1.55, marginBottom: 16 }}>
            {selected.description}
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 18 }}>
            <InfoTile label="Source" value={selected.ip} />
            <InfoTile label="Detected" value={fmtTime(selected.time)} />
            <InfoTile label="Tactic" value={selected.tactic} />
            <InfoTile label="Technique" value={`${selected.techniqueId}`} />
          </div>

          <div style={{ fontSize: 12, color: COLORS.textMuted, marginBottom: 8, fontWeight: 500 }}>Recommended mitigation</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {selected.mitigations.map((m, idx) => {
              const key = `${selected.id}:${idx}`;
              const done = mitigatedIds.has(key);
              return (
                <button
                  key={idx}
                  onClick={() => toggleMitigation(selected.id, idx)}
                  style={{
                    display: "flex", alignItems: "flex-start", gap: 8, textAlign: "left",
                    background: COLORS.panelAlt, border: `1px solid ${COLORS.borderSoft}`, borderRadius: 7,
                    padding: "9px 10px", cursor: "pointer", fontSize: 12.5,
                    color: done ? COLORS.textMuted : COLORS.text,
                    textDecoration: done ? "line-through" : "none",
                  }}
                >
                  {done ? <CheckCircle2 size={15} color={COLORS.low} style={{ flexShrink: 0, marginTop: 1 }} /> : <Circle size={15} color={COLORS.textFaint} style={{ flexShrink: 0, marginTop: 1 }} />}
                  {m}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function InfoTile({ label, value }) {
  return (
    <div style={{ background: COLORS.panelAlt, border: `1px solid ${COLORS.borderSoft}`, borderRadius: 7, padding: "8px 10px" }}>
      <div style={{ fontSize: 10, color: COLORS.textMuted, marginBottom: 3 }}>{label}</div>
      <div style={{ fontSize: 12.5, fontFamily: "'JetBrains Mono', monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value}</div>
    </div>
  );
}
