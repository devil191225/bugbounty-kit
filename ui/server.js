/**
 * RECON-AI Bug Bounty Dashboard — Backend Server
 * Express + WebSocket server for real-time Claude/tool streaming
 *
 * Run from WSL2:
 *   cd /mnt/c/Users/ask92/Downloads/bugbounty-kit/ui
 *   npm install && node server.js
 */

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const chokidar = require('chokidar');
const fs = require('fs');
const path = require('path');
const { spawn, exec } = require('child_process');
const os = require('os');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ── Kit root (works from both Windows and WSL paths) ──────────────────────────
const isWSL = os.platform() === 'linux' && fs.existsSync('/proc/version') &&
  fs.readFileSync('/proc/version', 'utf8').toLowerCase().includes('microsoft');
const isWindows = os.platform() === 'win32';

const KIT_ROOT = isWSL
  ? '/mnt/c/Users/ask92/Downloads/bugbounty-kit'
  : path.resolve(__dirname, '..');

const kitPath = (...parts) => path.join(KIT_ROOT, ...parts);

// ── Broadcast to all WS clients ───────────────────────────────────────────────
function broadcast(type, data) {
  const msg = JSON.stringify({ type, data, ts: Date.now() });
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(msg); });
}

// ── File helpers ──────────────────────────────────────────────────────────────
function readFile(p) {
  try { return fs.readFileSync(p, 'utf8'); } catch { return ''; }
}

function writeFile(p, content) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content, 'utf8');
}

function listDir(p) {
  try { return fs.readdirSync(p).filter(f => !f.startsWith('.')); } catch { return []; }
}

// ── File watcher — broadcast state changes to all clients ────────────────────
const watchPaths = [
  kitPath('SESSION.md'),
  kitPath('SCOPE.md'),
  kitPath('reports'),
  kitPath('sessions'),
];

chokidar.watch(watchPaths, { ignoreInitial: true, usePolling: isWindows })
  .on('change', (fp) => broadcast('file_changed', { path: fp, content: readFile(fp) }))
  .on('add', (fp) => broadcast('file_added', { path: fp }));

// ── Parse SESSION.md into structured state ────────────────────────────────────
function parseSession() {
  const raw = readFile(kitPath('SESSION.md'));
  const get = (key) => { const m = raw.match(new RegExp(`${key}=(.+)`)); return m ? m[1].trim() : ''; };

  const findingsTable = [];
  const tableMatch = raw.match(/## Findings Registry[\s\S]*?\n\|(.*)\n\|([-|]+)\n([\s\S]*?)(?:\n##|$)/);
  if (tableMatch) {
    const rows = tableMatch[3].trim().split('\n').filter(r => r.includes('|'));
    rows.forEach(row => {
      const cols = row.split('|').map(c => c.trim()).filter(Boolean);
      if (cols.length >= 5 && cols[0] && cols[0] !== 'ID') {
        findingsTable.push({ id: cols[0], title: cols[1], severity: cols[2], target: cols[3], status: cols[4], cvss: cols[5] || '' });
      }
    });
  }

  const nextSteps = [];
  const nsMatch = raw.match(/## Next Steps[\s\S]*?```([\s\S]*?)```/);
  if (nsMatch) {
    nsMatch[1].trim().split('\n').filter(Boolean).forEach(l => nextSteps.push(l.trim()));
  }

  return {
    lastUpdated: get('LAST_UPDATED'),
    phase: get('PHASE'),
    target: get('CURRENT_TARGET'),
    sessionId: get('SESSION_ID'),
    findings: findingsTable,
    nextSteps,
    raw,
  };
}

// ── Parse SCOPE.md ────────────────────────────────────────────────────────────
function parseScope() {
  const raw = readFile(kitPath('SCOPE.md'));
  return {
    programName: (raw.match(/PROGRAM_NAME=(.*)/) || [])[1]?.trim() || '',
    platform: (raw.match(/PLATFORM=(.*)/) || [])[1]?.trim() || '',
    programUrl: (raw.match(/PROGRAM_URL=(.*)/) || [])[1]?.trim() || '',
    maxSeverity: (raw.match(/MAX_SEVERITY=(.*)/) || [])[1]?.trim() || '',
    raw,
  };
}

// ── List reports ──────────────────────────────────────────────────────────────
function listReports() {
  return listDir(kitPath('reports')).map(f => ({
    filename: f,
    content: readFile(kitPath('reports', f)),
    modified: (() => { try { return fs.statSync(kitPath('reports', f)).mtime; } catch { return null; } })(),
  }));
}

// ── Active processes ──────────────────────────────────────────────────────────
const activeProcs = new Map();

function spawnCommand(cmdId, cmdArgs, cwd, env = {}) {
  const shell = isWSL ? '/bin/bash' : (isWindows ? 'wsl' : '/bin/bash');
  const args = isWindows
    ? ['bash', '-c', `cd "${KIT_ROOT.replace(/\\/g, '/')}" && ${cmdArgs.join(' ')}`]
    : ['-c', cmdArgs.join(' ')];

  broadcast('proc_start', { cmdId });

  const proc = spawn(shell, args, {
    cwd: isWSL ? KIT_ROOT : undefined,
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  activeProcs.set(cmdId, proc);

  proc.stdout.on('data', d => broadcast('proc_stdout', { cmdId, data: d.toString() }));
  proc.stderr.on('data', d => broadcast('proc_stderr', { cmdId, data: d.toString() }));
  proc.on('close', code => {
    activeProcs.delete(cmdId);
    broadcast('proc_done', { cmdId, code });
  });

  return proc;
}

// ── API Routes ────────────────────────────────────────────────────────────────

app.get('/api/state', (req, res) => {
  res.json({
    session: parseSession(),
    scope: parseScope(),
    reports: listReports(),
    toolStatus: checkTools(),
  });
});

app.get('/api/session', (req, res) => res.json(parseSession()));
app.get('/api/scope', (req, res) => res.json(parseScope()));
app.get('/api/scope/raw', (req, res) => res.send(readFile(kitPath('SCOPE.md'))));

app.post('/api/scope', (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'content required' });
  writeFile(kitPath('SCOPE.md'), content);
  res.json({ ok: true });
});

app.get('/api/reports', (req, res) => res.json(listReports()));

app.get('/api/report/:filename', (req, res) => {
  const fp = kitPath('reports', req.params.filename);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'not found' });
  res.send(readFile(fp));
});

// Run a named phase via Claude Code
app.post('/api/run/phase', (req, res) => {
  const { phase, target, extra } = req.body;
  const scope = parseScope();
  const tgt = target || scope.programName || 'the configured target';

  const phasePrompts = {
    'passive-recon': `Read CLAUDE.md and SCOPE.md. Then run full passive recon on ${tgt}: cert transparency, Shodan, GitHub dorking, Wayback URLs. Log everything to SESSION.md.`,
    'active-recon': `Read CLAUDE.md and SCOPE.md. Run active recon on ${tgt}: subdomain enum with subfinder, HTTP probe with httpx, port scan with naabu. Log to SESSION.md.`,
    'surface-map': `Read CLAUDE.md and SCOPE.md. Run surface mapping on ${tgt}: crawl with katana, URL collection with gau, JS analysis for secrets and endpoints. Log to SESSION.md.`,
    'vuln-hunt': `Read CLAUDE.md and SCOPE.md. Run vulnerability hunt on ${tgt}: nuclei scan, then targeted testing for IDOR, XSS, SQLi, auth bypass. Log all findings to SESSION.md and reports/.`,
    'chain-analysis': `Read CLAUDE.md, SCOPE.md, and all files in reports/. Analyze if any findings can be chained for higher impact. Document chains in SESSION.md.`,
    'report': `Read CLAUDE.md and all files in reports/. Write professional HackerOne-format reports for all CONFIRMED findings in reports/. ${extra || ''}`,
    'custom': extra || 'Read CLAUDE.md and SCOPE.md, then continue from SESSION.md next steps.',
  };

  const prompt = phasePrompts[phase] || phasePrompts['custom'];
  const cmdId = `${phase}-${Date.now()}`;

  // Kill any existing process for this phase
  for (const [id, proc] of activeProcs.entries()) {
    if (id.startsWith(phase)) { proc.kill(); activeProcs.delete(id); }
  }

  const claudeCmd = `claude --print "${prompt.replace(/"/g, '\\"')}"`;
  spawnCommand(cmdId, [claudeCmd], KIT_ROOT);

  res.json({ ok: true, cmdId });
});

// Run an arbitrary shell command
app.post('/api/run/cmd', (req, res) => {
  const { cmd } = req.body;
  if (!cmd) return res.status(400).json({ error: 'cmd required' });
  const cmdId = `cmd-${Date.now()}`;
  spawnCommand(cmdId, [cmd], KIT_ROOT);
  res.json({ ok: true, cmdId });
});

// Kill a running process
app.post('/api/run/kill/:cmdId', (req, res) => {
  const proc = activeProcs.get(req.params.cmdId);
  if (proc) { proc.kill(); activeProcs.delete(req.params.cmdId); }
  res.json({ ok: true });
});

// Check installed tools
function checkTools() {
  const tools = ['subfinder', 'httpx', 'nuclei', 'katana', 'gau', 'ffuf', 'dalfox', 'sqlmap', 'nmap', 'amass'];
  const results = {};
  tools.forEach(t => {
    try {
      const r = require('child_process').execSync(
        isWindows ? `wsl which ${t} 2>/dev/null` : `which ${t} 2>/dev/null`,
        { encoding: 'utf8', timeout: 2000 }
      ).trim();
      results[t] = r ? 'installed' : 'missing';
    } catch { results[t] = 'missing'; }
  });
  return results;
}

app.get('/api/tools', (req, res) => res.json(checkTools()));

// Run tool installer
app.post('/api/install', (req, res) => {
  const cmdId = 'install-tools';
  const cmd = isWindows
    ? 'wsl bash -c "cd /mnt/c/Users/ask92/Downloads/bugbounty-kit && bash scripts/install-tools.sh"'
    : 'bash scripts/install-tools.sh';
  spawnCommand(cmdId, [cmd], KIT_ROOT);
  res.json({ ok: true, cmdId });
});

// WebSocket: just echo pings for now, state changes are pushed proactively
wss.on('connection', (ws) => {
  ws.send(JSON.stringify({ type: 'connected', data: { kitRoot: KIT_ROOT } }));
  // Send current state on connect
  ws.send(JSON.stringify({ type: 'state', data: {
    session: parseSession(),
    scope: parseScope(),
    reports: listReports(),
  }}));
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════════════╗`);
  console.log(`║   RECON-AI Dashboard                     ║`);
  console.log(`║   http://localhost:${PORT}                   ║`);
  console.log(`╚══════════════════════════════════════════╝\n`);
  console.log(`Kit root: ${KIT_ROOT}`);
  console.log(`Platform: ${isWSL ? 'WSL2' : isWindows ? 'Windows' : 'Linux'}`);
});
