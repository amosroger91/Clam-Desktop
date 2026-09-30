const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { createStore } = require('./store.cjs');
const { runTool } = require('./analysis-tools.cjs');

const repository = 'Neo23x0/signature-base';
const files = [
  'apt_cobaltstrike.yar',
  'crime_emotet.yar',
  'crime_ransom_conti.yar',
  'crime_ransom_darkside.yar',
  'crime_maze_ransomware.yar',
  'crime_dearcry_ransom.yar',
  'apt_webshell_chinachopper.yar'
];
const spec = {
  version: 1,
  fallback: () => null,
  migrations: {},
  validate: value => {
    if (value !== null && (!/^[a-f0-9]{40}$/.test(value.version) || !/^[a-f0-9]{64}$/.test(value.digest)))
      throw Error('Invalid rule manifest');
    return { value, problems: [] };
  }
};
async function fetchBounded(url, limit, json = false) {
  const response = await fetch(url, {
    headers: { 'User-Agent': 'Sentinel-AV', Accept: 'application/vnd.github+json' },
    signal: AbortSignal.timeout(30000)
  });
  if (!response.ok) throw Error('Rule update HTTP ' + response.status);
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > limit) throw Error('Rule download exceeds limit');
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks);
  return json ? JSON.parse(bytes) : bytes;
}
function createRuleFeed(root, executable) {
  const store = createStore(root);
  const loaded = store.load('active', spec);
  let current = loaded.issue ? null : loaded.value,
    lastError = loaded.issue?.message || null,
    updating = null;
  function active() {
    if (!current) return null;
    const file = path.join(root, current.version, 'rules.yarc');
    if (!fs.existsSync(file)) return null;
    return { ...current, path: file };
  }
  // Verify the compiled file at startup; each scan uses the immutable version path.
  if (current) {
    const file = active()?.path;
    if (!file || crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') !== current.digest) {
      current = null;
      lastError = 'Active YARA rules failed their integrity check';
    }
  }
  async function update() {
    if (updating) return updating;
    updating = (async () => {
      const commit = await fetchBounded(`https://api.github.com/repos/${repository}/commits/master`, 2 * 1048576, true);
      if (!/^[a-f0-9]{40}$/.test(commit.sha)) throw Error('Invalid feed revision');
      if (current?.version === commit.sha) return current;
      const folder = path.join(root, commit.sha);
      fs.mkdirSync(folder, { recursive: true });
      for (const name of ['LICENSE', ...files.map(f => 'yara/' + f)]) {
        const bytes = await fetchBounded(
          `https://raw.githubusercontent.com/${repository}/${commit.sha}/${name}`,
          2 * 1048576
        );
        // Includes could read files outside this version. This curated feed is self-contained.
        if (name !== 'LICENSE' && /^\s*include\s+"/m.test(bytes.toString()))
          throw Error('Rule feed contains an unsupported include');
        fs.writeFileSync(path.join(folder, path.basename(name)), bytes);
      }
      const compiled = path.join(folder, 'rules.yarc');
      await runTool(
        executable,
        ['compile', '--path-as-namespace', '--output', compiled, ...files.map(f => path.join(folder, f))],
        { timeout: 120000 }
      );
      const probe = path.join(folder, 'clean-probe.txt');
      fs.writeFileSync(probe, 'Sentinel benign rule activation check.\n');
      const output = await runTool(executable, ['scan', '-C', '--output-format=json', compiled, probe]);
      const results = JSON.parse(output);
      if (!Array.isArray(results.matches) || results.matches.length)
        throw Error('Rule activation clean probe was flagged');
      const next = {
        version: commit.sha,
        digest: crypto.createHash('sha256').update(fs.readFileSync(compiled)).digest('hex'),
        updated: new Date().toISOString(),
        source: `https://github.com/${repository}/tree/${commit.sha}`,
        files
      };
      store.save('active', next, 1); // Atomic pointer switch only after compile and validation.
      current = next;
      lastError = null;
      return next;
    })()
      .catch(err => {
        lastError = err.message;
        throw err;
      })
      .finally(() => {
        updating = null;
      });
    return updating;
  }
  return { active, update, status: () => ({ ...current, error: lastError, updating: !!updating }) };
}
module.exports = { createRuleFeed, files };
