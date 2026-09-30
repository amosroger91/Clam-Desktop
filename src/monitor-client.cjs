const path = require('node:path');
const fs = require('node:fs');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const rpc = require('./monitor-rpc.cjs');

function createClient(
  root,
  { executable = process.execPath, agent = path.join(__dirname, 'monitor-agent.cjs'), host } = {}
) {
  const secret = rpc.token(root, true);
  let launching,
    leaseDepth = 0,
    leaseTimer,
    renewalError = null;
  const leaseId = crypto.randomUUID();
  const call = (action, payload, timeout) => rpc.request(root, secret, action, payload, timeout);
  async function ensure() {
    try {
      await call('status', null, 1000);
      return;
    } catch {}
    if (launching) return launching;
    launching = (async () => {
      const logPath = path.join(root, 'monitor', 'agent-start.log');
      const log = fs.openSync(logPath, 'w');
      const child = spawn(host || executable, host ? [executable, agent, root, '--console'] : [agent, root], {
        windowsHide: true,
        detached: true,
        stdio: ['ignore', log, log],
        env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }
      });
      fs.closeSync(log);
      let failure;
      child.on('error', err => {
        failure = err;
      });
      child.unref();
      for (let i = 0; i < 300; i++) {
        if (failure) throw failure;
        try {
          await call('status', null, 500);
          return;
        } catch {}
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      const detail = fs.readFileSync(logPath, 'utf8').slice(-2000);
      throw Error('The background scanner could not start. ' + (detail || 'Check the service or restart Sentinel.'));
    })().finally(() => {
      launching = null;
    });
    return launching;
  }
  async function configure(config) {
    await ensure();
    return call('configure', config, 30000);
  }
  async function acquire() {
    if (leaseDepth) {
      leaseDepth++;
      return;
    }
    await call('lease', { id: leaseId }, 30000);
    leaseDepth = 1;
    renewalError = null;
    leaseTimer = setInterval(
      () =>
        call('lease', { id: leaseId }).catch(err => {
          renewalError = err;
        }),
      10000
    );
    leaseTimer.unref();
  }
  async function release() {
    if (!leaseDepth || --leaseDepth) return;
    clearInterval(leaseTimer);
    await call('release', leaseId).catch(() => {});
  }
  return {
    call,
    ensure,
    configure,
    acquire,
    release,
    get renewalError() {
      return renewalError;
    },
    connected: () => fs.existsSync(path.join(root, 'monitor', 'config.json'))
  };
}

module.exports = { createClient };
