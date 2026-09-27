const fs = require('node:fs');
const path = require('node:path');

function nextRun(schedule, after = new Date()) {
  const [hour, minute] = schedule.time.split(':').map(Number);
  const next = new Date(after);
  next.setHours(hour, minute, 0, 0);
  if (schedule.frequency === 'weekly') {
    next.setDate(next.getDate() + (schedule.day - next.getDay() + 7) % 7);
    if (next <= after) next.setDate(next.getDate() + 7);
  } else if (next <= after) next.setDate(next.getDate() + 1);
  return next.toISOString();
}
function defaults() {
  return {
    engineDir: '', launchAtLogin: false, notifications: true, closeToTray: true,
    autoUpdate: true, scanArchives: true, detectPUA: false, exclusions: [],
    schedules: [
      { id: 'quick', enabled: true, frequency: 'daily', time: '12:00', day: 0 },
      { id: 'full', enabled: true, frequency: 'weekly', time: '18:00', day: 0 }
    ].map(s => ({ ...s, next: nextRun(s) }))
  };
}
function validateSettings(input, previous) {
  const out = { ...previous };
  for (const key of ['launchAtLogin', 'notifications', 'closeToTray', 'autoUpdate', 'scanArchives', 'detectPUA']) {
    if (typeof input[key] !== 'boolean') throw Error('Invalid preference: ' + key);
    out[key] = input[key];
  }
  if (!Array.isArray(input.schedules) || input.schedules.length !== 2) throw Error('Two scan schedules are required.');
  out.schedules = ['quick', 'full'].map(id => {
    const s = input.schedules.find(s => s.id === id);
    if (!s || typeof s.enabled !== 'boolean' || !['daily', 'weekly'].includes(s.frequency) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(s.time) || !Number.isInteger(s.day) || s.day < 0 || s.day > 6) throw Error('Invalid schedule.');
    const clean = { id, enabled: s.enabled, frequency: s.frequency, time: s.time, day: s.day };
    const old = previous.schedules.find(s => s.id === id);
    clean.next = ['enabled', 'frequency', 'time', 'day'].every(k => old[k] === clean[k]) ? old.next : nextRun(clean);
    return clean;
  });
  return out;
}
function scanArgs(settings, database, targets) {
  return ['--recursive=yes', '--verbose', '--stdout', '--database=' + database,
    '--scan-archive=' + (settings.scanArchives ? 'yes' : 'no'),
    '--detect-pua=' + (settings.detectPUA ? 'yes' : 'no'),
    ...settings.exclusions.map(p => '--exclude-dir=^' + p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([\\\\/]|$)'),
    ...targets];
}
function parseLine(line) {
  const found = line.match(/^(.*): (.+) FOUND$/);
  if (found) return { type: 'threat', path: found[1], signature: found[2] };
  if (/: OK$/.test(line)) return { type: 'file', path: line.slice(0, -4) };
  const count = line.match(/^Scanned files:\s*(\d+)/);
  if (count) return { type: 'count', count: Number(count[1]) };
  if (/ERROR|WARNING|Access is denied/i.test(line)) return { type: 'warning', message: line };
  return { type: 'info', message: line };
}
function saveJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file + '.tmp', JSON.stringify(data, null, 2));
  fs.renameSync(file + '.tmp', file);
}
module.exports = { nextRun, defaults, validateSettings, scanArgs, parseLine, saveJson };
