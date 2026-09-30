const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');
const os = require('node:os');

function findTool(root, name) {
  if (!root || !fs.existsSync(root)) return null;
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const file = path.join(root, entry.name);
    if (entry.isFile() && entry.name.toLowerCase() === name.toLowerCase()) return file;
    if (entry.isDirectory()) {
      const found = findTool(file, name);
      if (found) return found;
    }
  }
  return null;
}
function runTool(exe, args, { signal, timeout = 30000, maxBuffer = 2 * 1048576 } = {}) {
  if (!exe) return Promise.reject(Error('Required analysis tool is not installed'));
  return new Promise((resolve, reject) => {
    const child = execFile(
      exe,
      args,
      {
        windowsHide: true,
        timeout,
        maxBuffer,
        signal,
        // Do not load arbitrary Radare2 plugins or user initialization scripts.
        env: { ...process.env, R2_NOPLUGINS: '1' }
      },
      (err, stdout, stderr) =>
        err ? reject(Error(path.basename(exe) + ': ' + (stderr || err.message).slice(-2048))) : resolve(stdout)
    );
    try {
      os.setPriority(child.pid, os.constants.priority.PRIORITY_BELOW_NORMAL);
    } catch {}
  });
}

function peFindings(data) {
  const sections = data.sections || [],
    imports = data.imports || [];
  const names = new Set(imports.map(i => (i.name || '').toLowerCase()));
  const findings = [];
  if (sections.some(s => /upx[012]|\.aspack|\.vmp[01]/i.test(s.name || '')))
    findings.push('Known executable packer section (also used by legitimate software)');
  if (sections.some(s => /w/.test(s.perm || '') && /x/.test(s.perm || '')))
    findings.push('A section is both writable and executable');
  if (['virtualallocex', 'writeprocessmemory', 'createremotethread'].every(n => names.has(n)))
    findings.push('Imports a combination commonly used for remote process injection');
  return findings;
}

class AnalysisPipeline {
  constructor({ toolsRoot, rules, prefs, clam, run = runTool }) {
    Object.assign(this, { rules, prefs, clam, run });
    this.yara = findTool(toolsRoot, 'yr.exe');
    this.rabin = findTool(toolsRoot, 'rabin2.exe');
  }
  async scan(file, options) {
    const verdict = await this.clam.scan(file, options);
    if (!verdict.clean)
      return {
        ...verdict,
        engine: 'ClamAV',
        action: /^PUA\.|^Heuristics\./.test(verdict.signature) ? 'review' : 'quarantine'
      };
    const warnings = [];
    if (this.prefs.yaraEnabled) {
      const active = this.rules.active();
      if (!active) throw Error('YARA is enabled but no validated rules are active');
      const output = await this.run(
        this.yara,
        [
          'scan',
          '-C',
          '--output-format=json',
          '--print-meta',
          '--disable-console-logs',
          '--threads=1',
          '--timeout=20',
          active.path,
          file
        ],
        options
      );
      const data = JSON.parse(output);
      if (!Array.isArray(data.matches)) throw Error('Invalid YARA response');
      const matches = data.matches;
      if (matches.length) {
        const labels = matches.slice(0, 10).map(m => {
          const meta = m.meta || m.metadata || {};
          return `${m.rule}${meta.author ? ' (author: ' + meta.author + ')' : ''}`;
        });
        // Remote/community rules cannot promote themselves into an automatic removal policy.
        return {
          ...verdict,
          clean: false,
          signature: 'YARA: ' + labels.join('; '),
          engine: 'YARA-X',
          action: 'review',
          rulesVersion: active.version
        };
      }
    }
    if (this.prefs.staticAnalysis && /\.(exe|dll|scr|com)$/i.test(file)) {
      const output = await this.run(this.rabin, ['-j', '-S', '-i', file], options);
      warnings.push(...peFindings(JSON.parse(output)));
    }
    if (warnings.length)
      return {
        ...verdict,
        clean: false,
        signature: 'Static review: ' + warnings.join('; '),
        engine: 'Radare2',
        action: 'review'
      };
    return verdict;
  }
}
module.exports = { findTool, runTool, peFindings, AnalysisPipeline };
