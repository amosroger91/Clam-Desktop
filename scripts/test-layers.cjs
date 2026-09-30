const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const assert = require('node:assert/strict');
const { AnalysisPipeline, findTool, runTool } = require('../src/analysis-tools.cjs');
const { createRuleFeed } = require('../src/rule-feed.cjs');
const { query } = require('../src/behavior.cjs');
async function main() {
  const toolsRoot = path.resolve('vendor');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-layer-check-'));
  try {
    const rule = path.join(root, 'test.yar'),
      compiled = path.join(root, 'test.yarc'),
      file = path.join(root, 'sample.exe');
    fs.writeFileSync(
      rule,
      'rule Sentinel_Harmless_Test { meta: author="Sentinel test suite" strings: $a="Sentinel harmless YARA integration fixture" condition: $a }'
    );
    fs.writeFileSync(file, 'Sentinel harmless YARA integration fixture');
    await runTool(findTool(toolsRoot, 'yr.exe'), ['compile', '-o', compiled, rule]);
    const pipeline = new AnalysisPipeline({
      toolsRoot,
      prefs: { yaraEnabled: true },
      rules: { active: () => ({ path: compiled, version: 'test' }) },
      clam: { scan: async () => ({ clean: true }) }
    });
    const verdict = await pipeline.scan(file);
    assert.equal(verdict.clean, false);
    assert.equal(verdict.action, 'review');
    assert.match(verdict.signature, /Sentinel test suite/);
    fs.writeFileSync(file, 'ordinary harmless text');
    assert.equal((await pipeline.scan(file)).clean, true);
    pipeline.prefs.yaraEnabled = false;
    pipeline.prefs.staticAnalysis = true;
    assert.equal((await pipeline.scan(path.resolve('service/SentinelMonitor.exe'))).clean, true);
    const rows = JSON.parse(
      await runTool(findTool(toolsRoot, 'osqueryi.exe'), ['--disable_extensions', '--disable_logging', '--json', query])
    );
    assert.ok(Array.isArray(rows) && rows.length > 0);
    const feed = createRuleFeed(path.resolve('test-output/rules'), findTool(toolsRoot, 'yr.exe'));
    await feed.update();
    assert.ok(feed.active());
    console.log(
      'Real YARA match and clean verdict, author attribution, PE inspection, osquery snapshots and community feed activation passed.'
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}
main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
