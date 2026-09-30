// Private, loopback-only ClamAV engine. No shell invocation; responses and deadlines are bounded.
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const crypto = require('node:crypto');

function command(port, text, { timeout = 120000, signal, stream, onChunk = () => {} } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(Error('Scan cancelled'));
    const socket = net.createConnection({ host: '127.0.0.1', port });
    let result = Buffer.alloc(0),
      settled = false;
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      stream?.destroy();
      socket.destroy();
      err ? reject(err) : resolve(value);
    };
    const abort = () => finish(Error('Scan cancelled'));
    const timer = setTimeout(() => finish(Error('ClamAV request timed out')), timeout);
    signal?.addEventListener('abort', abort, { once: true });
    socket.on('error', err => finish(err));
    stream?.on('error', err => finish(err));
    socket.on('end', () => finish(Error('ClamAV closed before returning a complete result')));
    socket.on('data', data => {
      result = Buffer.concat([result, data]);
      if (result.length > 65536) return finish(Error('ClamAV response exceeded its limit'));
      const end = result.indexOf(0);
      if (end >= 0) finish(null, result.subarray(0, end).toString('utf8'));
    });
    socket.on('connect', async () => {
      try {
        socket.write('z' + text + '\0');
        if (stream) {
          for await (const chunk of stream) {
            if (settled) return;
            onChunk(chunk);
            const length = Buffer.alloc(4);
            length.writeUInt32BE(chunk.length);
            if (!socket.write(Buffer.concat([length, chunk]))) await once(socket, 'drain');
          }
          if (!settled) socket.write(Buffer.alloc(4));
        }
      } catch (err) {
        finish(err);
      }
    });
  });
}

async function availablePort() {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

function configText(database, port, prefs, options) {
  if (/[\r\n"\0]/.test(database)) throw Error('Invalid database directory');
  return (
    [
      'Foreground yes',
      `DatabaseDirectory "${database}"`,
      'TCPAddr 127.0.0.1',
      `TCPSocket ${port}`,
      `MaxThreads ${prefs.concurrency}`,
      `MaxQueue ${prefs.concurrency * 2 + 2}`,
      `StreamMaxLength ${prefs.maxFileMB}M`,
      `MaxFileSize ${prefs.maxFileMB}M`,
      `MaxScanSize ${Math.min(prefs.maxFileMB * 2, 2048)}M`,
      'MaxScanTime 60000',
      'ReadTimeout 120',
      'CommandReadTimeout 10',
      'ConcurrentDatabaseReload no',
      'AlertExceedsMax yes',
      `ScanArchive ${options.scanArchives ? 'yes' : 'no'}`,
      `DetectPUA ${options.detectPUA ? 'yes' : 'no'}`,
      'LogTime yes',
      'LogFileMaxSize 2M',
      'LogRotate yes'
    ].join('\n') + '\n'
  );
}

class Clamd {
  constructor({ dir, database, engineDir, prefs, options, spawnProcess = spawn }) {
    Object.assign(this, { dir, database, engineDir, prefs, options, spawnProcess });
    this.proc = null;
    this.starting = null;
    this.ready = false;
    this.error = null;
    this.generation = 0;
  }
  async start() {
    if (this.ready && this.proc?.exitCode === null) return;
    if (this.starting) return this.starting;
    this.starting = this.launch().finally(() => {
      this.starting = null;
    });
    return this.starting;
  }
  async launch() {
    this.port = await availablePort();
    if (this.stopped) throw Error('Engine startup cancelled');
    fs.mkdirSync(this.dir, { recursive: true });
    const config = path.join(this.dir, 'clamd.conf');
    fs.writeFileSync(config, configText(this.database, this.port, this.prefs, this.options));
    this.error = null;
    this.proc = this.spawnProcess(path.join(this.engineDir, 'clamd.exe'), ['--config-file=' + config], {
      windowsHide: true
    });
    const child = this.proc;
    let tail = '';
    const output = chunk => {
      tail = (tail + chunk.toString()).slice(-4096);
    };
    child.stdout.on('data', output);
    child.stderr.on('data', output);
    child.on('error', err => {
      this.error = err.message;
      this.ready = false;
    });
    child.on('exit', () => {
      this.ready = false;
      this.error = tail || 'ClamAV stopped';
    });
    if (this.prefs.lowPriority) {
      try {
        os.setPriority(child.pid, os.constants.priority.PRIORITY_BELOW_NORMAL);
      } catch {}
    }
    const deadline = Date.now() + 120000;
    while (Date.now() < deadline && child.exitCode === null && !this.error && !this.stopped) {
      try {
        if ((await command(this.port, 'PING', { timeout: 1000 })) === 'PONG') {
          this.ready = true;
          this.generation++;
          return;
        }
      } catch {}
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    await this.stop();
    throw Error(this.error || tail || 'ClamAV did not become ready within two minutes');
  }
  async scan(file, { signal } = {}) {
    await this.start();
    // INSTREAM scans the bytes of an open file; paths never enter the command protocol.
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(file);
    const result = await command(this.port, 'INSTREAM', { signal, stream, onChunk: chunk => hash.update(chunk) });
    const sha256 = hash.digest('hex');
    if (result === 'stream: OK') return { clean: true, sha256 };
    const found = /^stream: (.+) FOUND$/.exec(result);
    if (found) {
      if (found[1].startsWith('Heuristics.Limits.Exceeded')) throw Error('Scan limit exceeded: ' + found[1]);
      return { clean: false, signature: found[1], sha256 };
    }
    throw Error(result || 'ClamAV returned no verdict');
  }
  async stop() {
    this.stopped = true;
    this.ready = false;
    const child = this.proc;
    if (!child || child.exitCode !== null) return;
    await command(this.port, 'SHUTDOWN', { timeout: 1000 }).catch(() => {});
    if (child.exitCode !== null) {
      this.proc = null;
      return;
    }
    await new Promise(resolve => {
      const timer = setTimeout(resolve, 5000);
      child.once('close', () => {
        clearTimeout(timer);
        resolve();
      });
      child.kill();
    });
    this.proc = null;
  }
}

module.exports = { command, configText, Clamd };
