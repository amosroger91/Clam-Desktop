// Pinned upstream Windows releases. Rebuilds never silently select a different engine.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const releases = {
  clamav: [
    'Cisco-Talos/clamav',
    'clamav-1.5.4',
    'clamav-1.5.4.win.x64.zip',
    '0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395'
  ],
  yara: [
    'VirusTotal/yara-x',
    'v1.21.0',
    'yara-x-v1.21.0-x86_64-pc-windows-msvc.zip',
    '0e2fc4d2f64df3eaa22129ad5bd074c968a5d80766ddec6183b73175e5c9da25'
  ],
  radare2: [
    'radareorg/radare2',
    '6.2.2',
    'radare2-6.2.2-w64.zip',
    '913e7d95e7458226a5e783240877f2c1d405398ab38ba176ce9b12e046e31f34'
  ],
  osquery: [
    'osquery/osquery',
    '5.23.1',
    'osquery-5.23.1.windows_x86_64.zip',
    '7bd411050ef6b5aae1b23956aec0dc5ce6e800c5656f0cd463ac70a6e1bdf30b'
  ]
};
async function main() {
  const root = path.resolve('vendor');
  fs.mkdirSync(root, { recursive: true });
  for (const [name, [repo, version, asset, digest]] of Object.entries(releases)) {
    const destination = path.join(root, name),
      marker = path.join(destination, 'verified.json');
    if (fs.existsSync(marker) && JSON.parse(fs.readFileSync(marker)).sha256 === digest) continue;
    const url = `https://github.com/${repo}/releases/download/${version}/${asset}`;
    const response = await fetch(url, { signal: AbortSignal.timeout(300000) });
    if (!response.ok) throw Error(`${name}: HTTP ${response.status}`);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > 300 * 1048576 || crypto.createHash('sha256').update(bytes).digest('hex') !== digest)
      throw Error(`${name}: digest mismatch`);
    const archive = path.join(root, name + '.zip');
    fs.writeFileSync(archive, bytes);
    const quote = s => "'" + s.replace(/'/g, "''") + "'";
    const script = `$ProgressPreference='SilentlyContinue'; Expand-Archive -LiteralPath ${quote(archive)} -DestinationPath ${quote(destination)} -Force -ErrorAction Stop`;
    execFileSync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
      { windowsHide: true }
    );
    fs.writeFileSync(marker, JSON.stringify({ repo, version, url, sha256: digest }, null, 2));
    fs.unlinkSync(archive);
    console.log(`${name} ${version} verified and extracted`);
  }
  // Flatten ClamAV's upstream archive directory for a stable packaged engine location.
  const clam = path.join(root, 'clamav');
  const nested = path.join(clam, 'clamav-1.5.4.win.x64');
  if (fs.existsSync(nested)) {
    for (const name of fs.readdirSync(nested))
      fs.cpSync(path.join(nested, name), path.join(clam, name), { recursive: true });
    fs.rmSync(nested, { recursive: true });
  }
  const licenseUrls = {
    yara: 'https://raw.githubusercontent.com/VirusTotal/yara-x/v1.21.0/LICENSE',
    radare2: 'https://raw.githubusercontent.com/radareorg/radare2/6.2.2/COPYING.md',
    clamav: 'https://raw.githubusercontent.com/Cisco-Talos/clamav/clamav-1.5.4/COPYING.txt'
  };
  for (const [name, url] of Object.entries(licenseUrls)) {
    const target = path.join(root, name, 'UPSTREAM-LICENSE.txt');
    if (fs.existsSync(target)) continue;
    const response = await fetch(url);
    if (!response.ok) throw Error('Could not obtain ' + name + ' license');
    fs.writeFileSync(target, await response.text());
  }
}
main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
