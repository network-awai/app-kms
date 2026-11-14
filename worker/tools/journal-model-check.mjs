import { test } from 'node:test';
import assert from 'node:assert/strict';
import { propose, replay } from './journal-model.mjs';

const command = (operation, kind, policyId) => ({ lineage:'synthetic', operation, kind, policyId });
const issue = () => propose([], command('one','issue','policy-a'), null).event;

test('replay verifies ordered transitions and retries bind operation to request', () => {
  const first = issue();
  const second = propose([first], command('two','change','policy-b'), first.hash).event;
  assert.equal(replay([first, second], 'synthetic').policyId, 'policy-b');
  assert.equal(propose([first, second], command('one','issue','policy-a'), null).duplicate, true);
  assert.throws(() => propose([first, second], command('one','issue','other'), null), /operation_id_conflict/);
  assert.throws(() => replay([first, { ...second, policyId:'tampered' }], 'synthetic'), /invalid_chain/);
  assert.throws(() => replay([second, first], 'synthetic'), /invalid_chain/);
});

test('competing appends cannot both commit under an atomic head compare', async () => {
  const first = issue(), events = [first];
  const candidates = [propose([...events], command('a','change','policy-b'), first.hash).event,
    propose([...events], command('b','revoke','policy-a'), first.hash).event];
  const append = async e => { if (events.at(-1).hash !== e.previous) return false; events.push(e); return true; };
  assert.deepEqual(await Promise.all(candidates.map(append)), [true, false]);
  assert.throws(() => propose(events, command('b','revoke','policy-a'), first.hash), /head_conflict/);
  assert.equal(replay(events, 'synthetic').policyId, 'policy-b');
});

test('committed revocation blocks later changes and ID reuse is rejected', () => {
  const first = issue();
  const changed = propose([first], command('two','change','policy-b'), first.hash).event;
  assert.throws(() => propose([first, changed], command('three','change','policy-a'), changed.hash), /reused_policy_id/);
  const revoked = propose([first, changed], command('four','revoke','policy-b'), changed.hash).event;
  assert.equal(replay([first, changed, revoked], 'synthetic').revoked, true);
  assert.throws(() => propose([first, changed, revoked], command('five','change','policy-c'), revoked.hash), /invalid_transition/);
});
