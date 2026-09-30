const path = require('node:path');

const defaults = () => ({
  enabled: false,
  highRiskOnly: true,
  autoQuarantine: true,
  yaraEnabled: false,
  staticAnalysis: false,
  telemetryEnabled: false,
  keepRunning: false,
  folders: [],
  concurrency: 1,
  settleMs: 1500,
  maxFileMB: 100,
  maxQueue: 5000,
  minFreeMemoryMB: 768,
  maxCpuPercent: 80,
  pauseOnBattery: true,
  idleOnly: false,
  idleSeconds: 120,
  lowPriority: true,
  pauseUntil: null
});

function validate(input, previous = defaults()) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw Error('Invalid monitoring preferences.');
  const out = { ...defaults(), ...previous };
  for (const key of [
    'highRiskOnly',
    'autoQuarantine',
    'yaraEnabled',
    'staticAnalysis',
    'telemetryEnabled',
    'keepRunning'
  ]) {
    if (input[key] !== undefined && typeof input[key] !== 'boolean')
      throw Error('Invalid monitoring preference: ' + key);
    if (input[key] !== undefined) out[key] = input[key];
  }
  for (const key of ['enabled', 'pauseOnBattery', 'idleOnly', 'lowPriority']) {
    if (typeof input[key] !== 'boolean') throw Error('Invalid monitoring preference: ' + key);
    out[key] = input[key];
  }
  for (const [key, min, max] of [
    ['concurrency', 1, 4],
    ['settleMs', 500, 30000],
    ['maxFileMB', 1, 1024],
    ['maxQueue', 100, 20000],
    ['minFreeMemoryMB', 128, 32768],
    ['maxCpuPercent', 10, 100],
    ['idleSeconds', 30, 3600]
  ]) {
    if (!Number.isInteger(input[key]) || input[key] < min || input[key] > max)
      throw Error(`${key} must be between ${min} and ${max}.`);
    out[key] = input[key];
  }
  if (
    !Array.isArray(input.folders) ||
    input.folders.length > 32 ||
    input.folders.some(
      p => typeof p !== 'string' || !/^[a-z]:[\\/]/i.test(p) || /[\x00-\x1f"\r\n]/.test(p) || p.length > 4096
    )
  )
    throw Error('Choose up to 32 local folders for monitoring.');
  out.folders = [
    ...new Map(input.folders.map(p => [path.win32.normalize(p).toLowerCase(), path.win32.normalize(p)])).values()
  ];
  // Pause is set only by a dedicated action, never by the settings form.
  return out;
}

function resourceReason(settings, { freeMB, battery, cpuPercent, idleSeconds, sessionKnown = true }, now = Date.now()) {
  if (!settings.enabled) return 'Monitoring is off';
  if (settings.pauseUntil && Date.parse(settings.pauseUntil) > now) return 'Paused until ' + settings.pauseUntil;
  if (freeMB < settings.minFreeMemoryMB) return 'Waiting for available memory';
  if (cpuPercent != null && cpuPercent >= settings.maxCpuPercent) return 'Waiting for lower system CPU use';
  if (settings.pauseOnBattery && battery == null) return 'Waiting for power status';
  if (settings.pauseOnBattery && battery) return 'Paused on battery';
  if (settings.idleOnly && (!sessionKnown || idleSeconds < settings.idleSeconds))
    return 'Waiting for the computer to be idle';
  return null;
}

module.exports = { defaults, validate, resourceReason };
