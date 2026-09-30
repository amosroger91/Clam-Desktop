const path = require('node:path');
const validPath = value =>
  typeof value === 'string' && path.isAbsolute(value) && value.length <= 32768 && !/[\0\r\n]/.test(value);
const uuid = value => typeof value === 'string' && /^[0-9a-f-]{36}$/i.test(value);
const fallback = () => ({ pending: [], cache: [], outbox: [], metrics: {}, recent: [] });
const queueSpec = {
  version: 1,
  fallback,
  migrations: {},
  validate(data) {
    const value = fallback(),
      problems = [];
    if (!data || typeof data !== 'object') return { value, problems: ['Queue state was not an object'] };
    const list = (name, limit, check) => {
      if (data[name] === undefined) return;
      if (!Array.isArray(data[name]) || data[name].length > limit) {
        problems.push('Invalid ' + name);
        return;
      }
      value[name] = data[name].filter(entry => {
        if (check(entry)) return true;
        problems.push('Invalid entry in ' + name);
        return false;
      });
    };
    list(
      'pending',
      20000,
      e =>
        e &&
        validPath(e.path) &&
        ['firstSeen', 'due', 'priority', 'attempts', 'revision'].every(k => Number.isFinite(e[k]) && e[k] >= 0)
    );
    list(
      'cache',
      20000,
      e => Array.isArray(e) && e.length === 2 && typeof e[0] === 'string' && typeof e[1] === 'string'
    );
    list(
      'outbox',
      1004,
      e =>
        e &&
        uuid(e.id) &&
        validPath(e.path) &&
        typeof e.signature === 'string' &&
        e.signature.length <= 32768 &&
        Number.isFinite(Date.parse(e.at))
    );
    list(
      'recent',
      50,
      e => e && typeof e.path === 'string' && typeof e.message === 'string' && Number.isFinite(Date.parse(e.at))
    );
    for (const key of ['scanned', 'detections', 'errors', 'skipped', 'overflows'])
      if (Number.isSafeInteger(data.metrics?.[key]) && data.metrics[key] >= 0) value.metrics[key] = data.metrics[key];
    return { value, problems };
  }
};
module.exports = { queueSpec };
