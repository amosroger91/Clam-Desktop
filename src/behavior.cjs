const { findTool, runTool } = require('./analysis-tools.cjs');
const path = require('node:path');
// Snapshot telemetry is deliberately described as snapshots: short-lived processes can be missed.
const query =
  'SELECT p.pid,p.parent,p.name,p.path,p.start_time,s.remote_address,s.remote_port FROM processes p LEFT JOIN process_open_sockets s ON p.pid=s.pid AND s.remote_port>0 LIMIT 2000;';
function findings(rows) {
  const processes = new Map(rows.map(r => [String(r.pid), r]));
  return rows
    .filter(r => {
      const parent = processes.get(String(r.parent));
      return (
        parent &&
        /^(winword|excel|powerpnt|outlook)\.exe$/i.test(parent.name) &&
        /^(powershell|pwsh|cmd|wscript|cscript|mshta)\.exe$/i.test(r.name)
      );
    })
    .map(r => ({
      pid: r.pid,
      parent: r.parent,
      name: r.name,
      path: r.path,
      message: 'Office application spawned a command or script interpreter; review this activity'
    }));
}
function createBehavior(toolsRoot) {
  const exe = findTool(toolsRoot, 'osqueryi.exe');
  let status = { enabled: false, mode: '60-second snapshots', alerts: [] },
    next = 0,
    busy = false;
  async function tick(enabled) {
    status.enabled = enabled;
    if (!enabled || busy || Date.now() < next) return;
    busy = true;
    next = Date.now() + 60000;
    try {
      const rows = JSON.parse(
        await runTool(exe, ['--disable_extensions', '--disable_logging', '--json', query], { timeout: 15000 })
      );
      const alerts = findings(rows);
      status = {
        enabled: true,
        mode: '60-second snapshots',
        at: new Date().toISOString(),
        processes: new Set(rows.map(r => r.pid)).size,
        connections: rows.filter(r => r.remote_address).length,
        alerts: alerts.slice(0, 20),
        error: null
      };
    } catch (err) {
      status.error = err.message;
    } finally {
      busy = false;
    }
  }
  return { tick, status: () => status };
}
module.exports = { createBehavior, findings, query };
