const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');

function selectAsset(release, arch) {
  const suffix = arch === 'arm64' ? '.win.arm64.zip' : arch === 'x64' ? '.win.x64.zip' : '.win.win32.zip';
  const asset = release.assets?.find(a => a.name.endsWith(suffix));
  if (!asset || !/^sha256:[a-f0-9]{64}$/.test(asset.digest || '')) throw Error('No verified Windows ClamAV download is available for this device.');
  if (!asset.browser_download_url.startsWith('https://github.com/Cisco-Talos/clamav/releases/download/')) throw Error('Untrusted engine download location.');
  return asset;
}
async function install(root, progress) {
  const response = await fetch('https://api.github.com/repos/Cisco-Talos/clamav/releases/latest', { headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'Sentinel-AV' }, signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw Error('Could not check ClamAV releases: HTTP ' + response.status);
  const release = await response.json();
  const asset = selectAsset(release, process.arch);
  progress('Downloading ' + asset.name + ' from Cisco Talos…');
  const download = await fetch(asset.browser_download_url, { signal: AbortSignal.timeout(900000) });
  if (!download.ok || !download.body) throw Error('Engine download failed: HTTP ' + download.status);
  const archive = path.join(root, 'engine-download.zip');
  const handle = await fs.promises.open(archive, 'w');
  const hash = crypto.createHash('sha256'); let received = 0, last = 0;
  try {
    for await (const chunk of download.body) {
      hash.update(chunk); await handle.writeFile(chunk); received += chunk.length;
      if (Date.now() - last > 500) { last = Date.now(); progress('Downloading ClamAV · ' + Math.round(received / asset.size * 100) + '% · ' + Math.round(received / 1048576) + ' MB'); }
    }
  } finally { await handle.close(); }
  if (received !== asset.size || hash.digest('hex') !== asset.digest.slice(7)) { fs.unlinkSync(archive); throw Error('ClamAV download failed its SHA-256 integrity check. Please retry.'); }
  progress('Download verified. Installing the ClamAV engine…');
  const destination = path.join(root, 'engine-' + crypto.randomUUID());
  const quote = s => "'" + s.replace(/'/g, "''") + "'";
  const script = 'Expand-Archive -LiteralPath ' + quote(archive) + ' -DestinationPath ' + quote(destination) + ' -ErrorAction Stop';
  await new Promise((resolve, reject) => execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { windowsHide: true, timeout: 300000 }, err => err ? reject(err) : resolve()));
  function find(dir) {
    if (fs.existsSync(path.join(dir, 'clamscan.exe'))) return dir;
    for (const item of fs.readdirSync(dir, { withFileTypes: true })) if (item.isDirectory()) { const found = find(path.join(dir, item.name)); if (found) return found; }
  }
  const engineDir = find(destination);
  if (!engineDir || !fs.existsSync(path.join(engineDir, 'freshclam.exe'))) throw Error('Downloaded archive is missing the required ClamAV executables.');
  fs.unlinkSync(archive);
  return engineDir;
}
module.exports = { install, selectAsset };
