// Isolated executable model, not a production journal or an authorization gate.
import { createHash } from 'node:crypto';

const digest = value => createHash('sha256').update(value).digest('hex');
const hex = /^[0-9a-f]{64}$/;
const fail = code => { throw new Error(code); };
const eventBytes = e => JSON.stringify({ schema:e.schema, lineage:e.lineage, sequence:e.sequence,
  previous:e.previous, operation:e.operation, requestHash:e.requestHash, kind:e.kind, policyId:e.policyId });
const eventHash = e => digest('kms-policy-event-v1\0' + eventBytes(e));
const requestHash = c => digest('kms-policy-command-v1\0' + JSON.stringify({
  lineage:c.lineage, kind:c.kind, policyId:c.policyId }));

// Replay verifies the whole chain. It cannot detect a valid tail that was omitted;
// externally authenticated checkpoints and durable storage are still required.
export function replay(events, lineage) {
  if (!Array.isArray(events) || typeof lineage !== 'string' || !lineage) fail('invalid_input');
  const state = { sequence:0, head:null, policyId:null, revoked:false,
    usedIds:new Set(), operations:new Map() };
  for (const e of events) {
    if (!e || e.schema !== 'kms.policy-event.v1' || e.lineage !== lineage ||
        e.sequence !== state.sequence + 1 || e.previous !== state.head ||
        typeof e.operation !== 'string' || !e.operation || !hex.test(e.requestHash) ||
        !hex.test(e.hash) || eventHash(e) !== e.hash) fail('invalid_chain');
    if (state.operations.has(e.operation)) fail('duplicate_operation');
    const command = { lineage, kind:e.kind, policyId:e.policyId };
    if (requestHash(command) !== e.requestHash) fail('request_mismatch');
    if (!['issue','change','revoke'].includes(e.kind) || typeof e.policyId !== 'string' || !e.policyId) fail('invalid_event');
    if (e.kind === 'issue') {
      if (state.sequence !== 0) fail('invalid_transition');
      state.usedIds.add(e.policyId); state.policyId = e.policyId;
    } else {
      if (!state.sequence || state.revoked) fail('invalid_transition');
      if (e.kind === 'change') {
        if (state.usedIds.has(e.policyId)) fail('reused_policy_id');
        state.usedIds.add(e.policyId); state.policyId = e.policyId;
      } else {
        if (e.policyId !== state.policyId) fail('invalid_transition');
        state.revoked = true;
      }
    }
    state.sequence = e.sequence; state.head = e.hash;
    state.operations.set(e.operation, { requestHash:e.requestHash, event:e });
  }
  return state;
}

// The caller must atomically append only if expectedHead still matches and must
// enforce operation-ID uniqueness in the same transaction. A timeout is unknown.
export function propose(events, command, expectedHead) {
  if (!command || typeof command.lineage !== 'string' || !command.lineage ||
      typeof command.operation !== 'string' || !command.operation ||
      !['issue','change','revoke'].includes(command.kind) ||
      typeof command.policyId !== 'string' || !command.policyId) fail('invalid_command');
  const state = replay(events, command.lineage), hash = requestHash(command);
  const prior = state.operations.get(command.operation);
  if (prior) {
    if (prior.requestHash !== hash) fail('operation_id_conflict');
    return { duplicate:true, event:prior.event };
  }
  if (state.head !== expectedHead) fail('head_conflict');
  const event = { schema:'kms.policy-event.v1', lineage:command.lineage,
    sequence:state.sequence + 1, previous:state.head, operation:command.operation,
    requestHash:hash, kind:command.kind, policyId:command.policyId };
  event.hash = eventHash(event);
  replay([...events, event], command.lineage); // validate transition before append
  return { duplicate:false, event };
}
