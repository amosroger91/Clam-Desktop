const fs = require('node:fs');
const path = require('node:path');
const { install } = require('../src/installer.cjs');

async function prepare() {
  const root = path.resolve('test-output');
  fs.mkdirSync(root, { recursive: true });
  const marker = path.join(root, 'engine-path.txt');
  if (fs.existsSync(marker) && fs.existsSync(path.join(fs.readFileSync(marker, 'utf8').trim(), 'clamd.exe'))) return;
  const dir = await install(root, message => console.log(message));
  fs.writeFileSync(marker, dir);
}
prepare().catch(err => {
  console.error(err.message);
  process.exitCode = 1;
});
