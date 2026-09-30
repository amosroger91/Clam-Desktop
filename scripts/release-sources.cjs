// Publish unmodified corresponding source archives alongside the bundled binary release.
const fs = require('node:fs');
const path = require('node:path');
async function main() {
  for (const [name, repo, tag] of [
    ['ClamAV-1.5.4-source.tar.gz', 'Cisco-Talos/clamav', 'clamav-1.5.4'],
    ['Radare2-6.2.2-source.tar.gz', 'radareorg/radare2', '6.2.2']
  ]) {
    const target = path.resolve('release', name);
    if (fs.existsSync(target)) continue;
    const response = await fetch(`https://codeload.github.com/${repo}/tar.gz/refs/tags/${tag}`, {
      signal: AbortSignal.timeout(180000)
    });
    if (!response.ok) throw Error('Source download HTTP ' + response.status);
    const handle = await fs.promises.open(target + '.partial', 'w');
    try {
      for await (const chunk of response.body) await handle.writeFile(chunk);
    } finally {
      await handle.close();
    }
    fs.renameSync(target + '.partial', target);
    console.log(name);
  }
}
main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
