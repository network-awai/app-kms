import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { inspectSnapshot } from './verify-legacy-snapshot.mjs';

const entry = (recipients, extra = {}) => {
  const policy = { resourcePattern: 'kagitaba://vault/demo/**', recipients, issuer: 'did:example:issuer' };
  const canonical = JSON.stringify({ ...policy, recipients: [...new Set(recipients)].sort() });
  const key = 'kms-sha256-' + createHash('sha256').update(canonical).digest('hex');
  return { key, value: JSON.stringify({ cid: key, policy, jwt: 'synthetic', createdAt: 't', updatedAt: 't', ...extra }) };
};
const codes = result => result.errors.map(e => e.code);

test('accepts a reciprocal chain and produces stable raw digests', () => {
  const a = entry(['did:example:b', 'did:example:a', 'did:example:a']);
  const b = entry(['did:example:b']);
  a.value = JSON.stringify({ ...JSON.parse(a.value), supersededBy: b.key });
  b.value = JSON.stringify({ ...JSON.parse(b.value), supersedes: a.key });
  const result = inspectSnapshot([b, a]);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result, inspectSnapshot([a, b]));
  assert.equal(result.inventory.find(x => x.key === a.key).sha256, createHash('sha256').update(a.value).digest('hex'));
  assert.ok(result.limitations.includes('jwt_signature_unverified'));
});

test('quarantines malformed, duplicate and content-mismatched records', () => {
  const a = entry([]), bad = { ...a, value: '{' };
  assert.ok(codes(inspectSnapshot([bad, a])).includes('duplicate_key'));
  assert.ok(codes(inspectSnapshot([bad])).includes('invalid_json'));
  assert.ok(codes(inspectSnapshot([{ ...a, value: a.value.replace('vault/demo', 'vault/other') }])).includes('policy_id_mismatch'));
  assert.ok(codes(inspectSnapshot([{ key: a.key, value: JSON.stringify({ policy: { recipients: [4] } }) }])).includes('invalid_record'));
});

test('detects missing, inconsistent, converging, cyclic and revoked links', () => {
  const a = entry(['did:a:1']), b = entry(['did:b:1']), c = entry(['did:c:1']);
  const set = (e, fields) => ({ ...e, value: JSON.stringify({ ...JSON.parse(e.value), ...fields }) });
  assert.ok(codes(inspectSnapshot([set(a, { supersededBy: b.key })])).includes('missing_or_invalid_link'));
  assert.ok(codes(inspectSnapshot([set(a, { supersededBy: b.key }), b])).includes('nonreciprocal_link'));
  const result = inspectSnapshot([set(a, { supersededBy: b.key, revoked: true }), set(c, { supersededBy: b.key }), set(b, { supersedes: a.key, supersededBy: a.key })]);
  for (const code of ['converging_links', 'cycle', 'revoked_predecessor']) assert.ok(codes(result).includes(code), code);
});

test('flags links beyond the legacy traversal limit', () => {
  const chain = Array.from({ length: 66 }, (_, i) => entry([`did:test:${i}`]));
  const linked = chain.map((e, i) => ({ ...e, value: JSON.stringify({ ...JSON.parse(e.value),
    ...(i ? { supersedes: chain[i-1].key } : {}), ...(i < 65 ? { supersededBy: chain[i+1].key } : {}) }) }));
  assert.ok(codes(inspectSnapshot(linked)).includes('chain_exceeds_64'));
});
