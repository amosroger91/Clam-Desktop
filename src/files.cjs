// File identity helpers. Hashing streams the file asynchronously so large files do not block the UI.
const nodeFs = require('node:fs');
const crypto = require('node:crypto');

function hashFile(file, fs = nodeFs) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    fs.createReadStream(file)
      .on('error', reject)
      .on('data', chunk => hash.update(chunk))
      .on('end', () => resolve(hash.digest('hex')));
  });
}

// Size and hash of a regular file, or null when it is missing. Throws for other access errors.
async function identify(file, fs = nodeFs) {
  let stat;
  try {
    stat = await fs.promises.lstat(file);
  } catch (err) {
    if (err.code === 'ENOENT' || err.code === 'ENOTDIR') return null;
    throw err;
  }
  if (!stat.isFile()) return { size: stat.size, sha256: null, regular: false };
  return { size: stat.size, sha256: await hashFile(file, fs), regular: true, modified: stat.mtime.toISOString() };
}

module.exports = { hashFile, identify };
