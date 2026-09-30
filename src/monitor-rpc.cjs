const net = require('node:net');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const fs = require('node:fs');
const { StringDecoder } = require('node:string_decoder');

function address(root) {
  const id = crypto.createHash('sha256').update(path.resolve(root).toLowerCase()).digest('hex').slice(0, 24);
  return process.platform === 'win32'
    ? `\\\\.\\pipe\\sentinel-monitor-${id}`
    : path.join(os.tmpdir(), `sentinel-${id}.sock`);
}
function token(root, create = false) {
  const file = path.join(root, 'monitor', 'control.key');
  if (create) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    try {
      fs.writeFileSync(file, crypto.randomBytes(32).toString('hex'), { flag: 'wx', mode: 0o600 });
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
    }
  }
  const value = fs.readFileSync(file, 'utf8').trim();
  if (!/^[a-f0-9]{64}$/.test(value)) throw Error('Invalid monitor control key');
  return value;
}
function request(root, secret, action, payload, timeout = 15000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(address(root));
    const decoder = new StringDecoder('utf8');
    let buffer = '',
      settled = false;
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      err ? reject(err) : resolve(value);
    };
    const timer = setTimeout(() => finish(Error('Background scanner did not respond')), timeout);
    socket.on('error', err => finish(err));
    socket.on('end', () => finish(Error('Background scanner disconnected')));
    socket.on('connect', () => socket.write(JSON.stringify({ token: secret, action, payload }) + '\n'));
    socket.on('data', chunk => {
      buffer += decoder.write(chunk);
      if (buffer.length > 2 * 1024 * 1024) return finish(Error('Monitor response too large'));
      if (!buffer.includes('\n')) return;
      try {
        const reply = JSON.parse(buffer.slice(0, buffer.indexOf('\n')));
        reply.ok ? finish(null, reply.data) : finish(Object.assign(Error(reply.error), { code: reply.code }));
      } catch (err) {
        finish(err);
      }
    });
  });
}
function server(root, secret, handler) {
  return net.createServer(socket => {
    const decoder = new StringDecoder('utf8');
    let buffer = '',
      received = false;
    socket.setTimeout(15000, () => socket.destroy());
    socket.on('error', () => {});
    socket.on('data', async chunk => {
      if (received) return;
      buffer += decoder.write(chunk);
      if (buffer.length > 128 * 1024) return socket.destroy();
      if (!buffer.includes('\n')) return;
      received = true;
      socket.setTimeout(180000);
      try {
        const msg = JSON.parse(buffer.slice(0, buffer.indexOf('\n')));
        const supplied = Buffer.from(typeof msg.token === 'string' ? msg.token : '');
        const expected = Buffer.from(secret);
        if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected))
          throw Error('Unauthorized');
        const data = await handler(msg.action, msg.payload);
        socket.end(JSON.stringify({ ok: true, data }) + '\n');
      } catch (err) {
        socket.end(JSON.stringify({ ok: false, error: err.message, code: err.code }) + '\n');
      }
    });
  });
}

module.exports = { address, token, request, server };
