// Synthetic-database harness, never packaged or enabled by a runtime environment switch.
const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
require('../../src/monitor-agent.cjs')
  .run(process.argv[2], {
    inspectDatabase: dir => ({
      present: true,
      fingerprint: crypto
        .createHash('sha256')
        .update(fs.readFileSync(path.join(dir, 'test.hdb')))
        .digest('hex')
    }),
    sampleResources: async () => ({ freeMB: 4096, battery: false, engineMB: 0 })
  })
  .catch(err => {
    console.error(err);
    process.exit(1);
  });
