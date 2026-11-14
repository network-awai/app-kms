// Offline inspection only. This does not fetch KV, verify signatures, or prove
// that the supplied records are a complete or point-in-time snapshot.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const sha = value => createHash('sha256').update(value).digest('hex');
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const idPattern = /^kms-sha256-[0-9a-f]{64}$/;

export function inspectSnapshot(entries) {
  if (!Array.isArray(entries)) throw new TypeError('snapshot must be an array');
  const errors = [], records = new Map(), inventory = [];
  const error = (code, key) => errors.push({ code, key });
  for (const entry of entries) {
    if (!isObject(entry) || typeof entry.key !== 'string' || typeof entry.value !== 'string') {
      error('invalid_entry', null); continue;
    }
    const { key, value } = entry;
    inventory.push({ key, bytes: Buffer.byteLength(value), sha256: sha(value) });
    if (records.has(key)) { error('duplicate_key', key); continue; }
    // Mark duplicates even when the first value cannot be parsed.
    records.set(key, null);
    if (!idPattern.test(key)) error('invalid_key', key);
    let record;
    try { record = JSON.parse(value); } catch { error('invalid_json', key); continue; }
    if (!isObject(record) || !isObject(record.policy)) { error('invalid_record', key); continue; }
    const p = record.policy;
    if (typeof p.resourcePattern !== 'string' || typeof p.issuer !== 'string' ||
        !Array.isArray(p.recipients) || !p.recipients.every(x => typeof x === 'string') ||
        typeof record.jwt !== 'string' || typeof record.createdAt !== 'string' ||
        typeof record.updatedAt !== 'string' || (record.revoked !== undefined && typeof record.revoked !== 'boolean') ||
        ['supersedes', 'supersededBy'].some(x => record[x] !== undefined &&
          (typeof record[x] !== 'string' || !idPattern.test(record[x])))) {
      error('invalid_record', key); continue;
    }
    const canonical = JSON.stringify({ resourcePattern: p.resourcePattern,
      recipients: [...new Set(p.recipients)].sort(), issuer: p.issuer });
    if (`kms-sha256-${sha(canonical)}` !== key || record.cid !== key) error('policy_id_mismatch', key);
    records.set(key, record);
  }
  const incoming = new Map();
  for (const [key, rec] of records) {
    if (!rec) continue;
    for (const [field, inverse] of [['supersededBy', 'supersedes'], ['supersedes', 'supersededBy']]) {
      const target = rec[field];
      if (!target) continue;
      const other = records.get(target);
      if (!other) error('missing_or_invalid_link', key);
      else if (other[inverse] !== key) error('nonreciprocal_link', key);
    }
    if (rec.supersededBy) incoming.set(rec.supersededBy, (incoming.get(rec.supersededBy) || 0) + 1);
    if (rec.revoked && rec.supersededBy) error('revoked_predecessor', key);
  }
  for (const [key, count] of incoming) if (count > 1) error('converging_links', key);
  for (const [start, rec] of records) {
    if (!rec) continue;
    const seen = new Set(); let key = start, steps = 0;
    while (records.get(key)) {
      if (seen.has(key)) { error('cycle', start); break; }
      seen.add(key);
      const next = records.get(key).supersededBy;
      if (!next) break;
      steps++;
      if (steps > 64) { error('chain_exceeds_64', start); break; }
      key = next;
    }
  }
  const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
  inventory.sort((a,b) => compare(a.key, b.key));
  errors.sort((a,b) => compare(`${a.code}:${a.key}`, `${b.code}:${b.key}`));
  return { schema: 'kms.legacy-snapshot-inspection.v1', count: entries.length, inventory, errors,
    limitations: ['input_completeness_unverified', 'point_in_time_consistency_unverified',
      'jwt_signature_unverified', 'historical_events_unrecoverable'] };
}

async function main() {
  if (process.argv.length !== 3) throw new Error('usage: node verify-legacy-snapshot.mjs snapshot.json');
  const result = inspectSnapshot(JSON.parse(await readFile(process.argv[2], 'utf8')));
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  if (result.errors.length) process.exitCode = 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => { process.stderr.write('Snapshot inspection failed; check input format and access.\n'); process.exitCode = 2; });
}
