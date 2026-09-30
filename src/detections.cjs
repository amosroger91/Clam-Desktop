// Durable detection records, independent of scan-report retention.
//
// A detection stays unresolved ('detected' or 'missing') until the user acts on it. Repeated sightings of
// the same file and signature while unresolved are merged into one record. Resolved records are kept for
// their audit trail; only the oldest resolved records are ever pruned, never unresolved ones.
const crypto = require('node:crypto');

const UNRESOLVED = ['detected', 'missing'];
const MAX_REPORT_LINKS = 20;
const MAX_AUDIT = 50;
const MAX_RESOLVED = 1000;
const MAX_REVISIONS = 10;

// Windows paths are case-insensitive.
const key = (file, signature) => file.toLowerCase() + '\n' + signature;
const isUnresolved = d => UNRESOLVED.includes(d.status);

function audit(d, at, action, detail = null) {
  d.audit.push({ at, action, detail });
  if (d.audit.length > MAX_AUDIT) d.audit.splice(1, d.audit.length - MAX_AUDIT);
}

// Records one sighting from a scan. Returns the detection it was merged into or created.
function observe(detections, { path, signature, reportId, at, id = crypto.randomUUID() }) {
  // A live detection may have been reviewed before its scan commits or replays.
  const recorded = detections.find(d => d.id === id);
  if (recorded) return recorded;
  const existing = detections.find(d => isUnresolved(d) && key(d.path, d.signature) === key(path, signature));
  if (existing) {
    // Replaying the same scan's sighting (for example after a crash) is a no-op.
    if (existing.reports.includes(reportId)) return existing;
    existing.lastSeen = at;
    existing.sightings++;
    existing.reports = [reportId, ...existing.reports].slice(0, MAX_REPORT_LINKS);
    // The file at this path may have changed since it was last identified. Keep the old identity as
    // history and require it to be re-established for this sighting; retry any earlier identity failure.
    if (existing.sha256) {
      existing.revisions = [
        {
          sha256: existing.sha256,
          size: existing.size,
          identifiedAt: existing.identifiedAt,
          reportId: existing.identifiedBy
        },
        ...(existing.revisions || [])
      ].slice(0, MAX_REVISIONS);
    }
    existing.sha256 = null;
    existing.size = null;
    delete existing.identifyError;
    if (existing.status === 'missing') {
      existing.status = 'detected';
      audit(existing, at, 'seen-again', reportId);
    }
    return existing;
  }
  const created = {
    id,
    path,
    signature,
    status: 'detected',
    firstSeen: at,
    lastSeen: at,
    sightings: 1,
    reports: [reportId],
    sha256: null,
    size: null,
    quarantineId: null,
    audit: []
  };
  audit(created, at, 'detected', reportId);
  detections.unshift(created);
  return created;
}

// Records the content identity established for the detection's latest sighting.
function recordIdentity(d, found, at) {
  const previous = d.revisions?.[0]?.sha256;
  Object.assign(d, { sha256: found.sha256, size: found.size, identifiedAt: at, identifiedBy: d.reports[0] });
  delete d.identifyError;
  if (previous && previous !== found.sha256) audit(d, at, 'content-changed', found.sha256);
}

function transition(d, status, at, action, detail = null) {
  d.status = status;
  audit(d, at, action, detail);
}

// Drops the oldest resolved records beyond the cap. Unresolved detections are always kept.
function prune(detections, maxResolved = MAX_RESOLVED) {
  let resolved = 0;
  return detections.filter(d => isUnresolved(d) || ++resolved <= maxResolved);
}

// Builds the detection store from version-0 scan reports, whose threats carried their own status.
// Returns the detections and a map from each old threat id to its detection id.
function migrateLegacy(legacyReports, at) {
  const detections = [],
    idMap = {};
  const reports = Array.isArray(legacyReports) ? [...legacyReports].reverse() : [];
  for (const report of reports) {
    for (const t of Array.isArray(report?.threats) ? report.threats : []) {
      if (typeof t?.id !== 'string' || typeof t.path !== 'string' || typeof t.signature !== 'string') continue;
      const seen = report.finished || report.started || at;
      if (!t.status || t.status === 'detected') {
        idMap[t.id] = observe(detections, { ...t, reportId: report.id, at: seen, id: t.id }).id;
      } else {
        const d = observe([], { ...t, reportId: report.id, at: seen, id: t.id });
        transition(
          d,
          t.status === 'restored' ? 'restored' : 'quarantined',
          at,
          'migrated',
          'Imported from an earlier version.'
        );
        d.quarantineId = t.id;
        detections.unshift(d);
        idMap[t.id] = t.id;
      }
    }
  }
  return { detections, idMap };
}

module.exports = { observe, recordIdentity, transition, prune, migrateLegacy, isUnresolved, UNRESOLVED };
