// Per-scan write-ahead journal: the durable record of a scan in progress.
//
// Each scan appends newline-delimited JSON records to journal/<scanId>.ndjson: a 'start' header, the
// resolved 'targets', one 'detection' per threat as it is reported, and a final 'commit' with the
// outcome. Every record is fsync'd before it is acknowledged and carries a sequence number and checksum,
// so a torn final line is recognized and ignored. The journal is independent of the size-capped
// diagnostic log, and is deleted only after its contents are applied to the stores.
const nodeFs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const MAX_JOURNAL_BYTES = 32 * 1024 * 1024;
const MAX_RECORD_BYTES = 64 * 1024;
const SCAN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const checksum = text => crypto.createHash('sha256').update(text).digest('hex').slice(0, 16);

class JournalError extends Error {
  constructor(message, cause) {
    super(message, { cause });
    this.name = 'JournalError';
    this.code = cause?.code;
  }
}

function createJournal(dir, { fs = nodeFs } = {}) {
  const fileFor = id => {
    if (!SCAN_ID.test(id)) throw new JournalError('Invalid scan id: ' + id);
    return path.join(dir, id + '.ndjson');
  };

  // Opens a new journal. Throws if the header cannot be made durable, so a scan never starts untracked.
  function begin(id, header) {
    const file = fileFor(id);
    let fd,
      seq = 0,
      bytes = 0;
    try {
      fs.mkdirSync(dir, { recursive: true });
      fd = fs.openSync(file, 'wx');
    } catch (err) {
      throw new JournalError('The scan journal could not be created: ' + err.message, err);
    }
    function append(type, data) {
      if (fd === null) throw new JournalError('The scan journal is closed.');
      const body = JSON.stringify({ seq: ++seq, type, ...data });
      if (body.length > MAX_RECORD_BYTES) throw new JournalError('A journal record exceeded its size limit.');
      const line = JSON.stringify({ c: checksum(body), r: JSON.parse(body) }) + '\n';
      if (bytes + line.length > MAX_JOURNAL_BYTES)
        throw new JournalError('The scan journal reached its size limit.', { code: 'EJOURNALFULL' });
      try {
        fs.writeSync(fd, line);
        fs.fsyncSync(fd);
        bytes += line.length;
      } catch (err) {
        throw new JournalError('Could not record scan evidence: ' + err.message, err);
      }
    }
    function close() {
      if (fd === null) return;
      try {
        fs.closeSync(fd);
      } catch {}
      fd = null;
    }
    try {
      append('start', { header });
    } catch (err) {
      close();
      try {
        fs.rmSync(file, { force: true });
      } catch {}
      throw err;
    }
    return { append, close, file };
  }

  // Reads a journal, reading at most MAX_JOURNAL_BYTES. Records after a torn or corrupt line are ignored.
  function read(id) {
    const file = fileFor(id);
    let text;
    const fd = fs.openSync(file, 'r');
    try {
      const size = Math.min(fs.fstatSync(fd).size, MAX_JOURNAL_BYTES);
      const buffer = Buffer.alloc(size);
      fs.readSync(fd, buffer, 0, size, 0);
      text = buffer.toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
    const replay = { id, header: null, targets: null, detections: [], progress: null, commit: null, torn: false };
    let expected = 1;
    for (const line of text.split('\n')) {
      if (!line) continue;
      let record;
      try {
        const parsed = JSON.parse(line);
        if (checksum(JSON.stringify(parsed.r)) !== parsed.c || parsed.r.seq !== expected) throw Error('mismatch');
        record = parsed.r;
      } catch {
        replay.torn = true;
        break;
      }
      expected++;
      if (record.type === 'start') replay.header = record.header;
      else if (record.type === 'targets') replay.targets = record.targets;
      else if (record.type === 'detection') replay.detections.push(record);
      else if (record.type === 'progress') replay.progress = record;
      else if (record.type === 'commit') replay.commit = record.outcome;
    }
    return replay;
  }

  function list() {
    try {
      return fs
        .readdirSync(dir)
        .filter(n => n.endsWith('.ndjson'))
        .map(n => n.slice(0, -7))
        .filter(id => SCAN_ID.test(id));
    } catch {
      return [];
    }
  }

  function remove(id) {
    fs.rmSync(fileFor(id), { force: true });
  }

  return { begin, read, list, remove };
}

module.exports = { createJournal, JournalError, SCAN_ID };
