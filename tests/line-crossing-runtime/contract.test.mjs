import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { after, before, test } from 'node:test'
import { fileURLToPath } from 'node:url'

const testRoot = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(testRoot, '../..')
const runtimeRoot = path.join(repoRoot, 'apps/line-crossing/ui/src/runtime')
const appSourceRoot = path.join(repoRoot, 'apps/line-crossing/ui/src')
const browserRunnerRoot = path.join(repoRoot, 'tests/line-crossing-ui/browser-runner')

let runtime
let bundleDir

before(async () => {
  const nodeRequire = createRequire(path.join(browserRunnerRoot, 'package.json'))
  const esbuild = nodeRequire('esbuild')
  bundleDir = mkdtempSync(path.join(tmpdir(), 'lc-runtime-contract.'))
  const outfile = path.join(bundleDir, 'runtime.mjs')
  await esbuild.build({
    stdin: {
      contents: [
        `export * from './bridgeProtocol.ts';`,
        `export * from './bridgeSession.ts';`,
        `export * from './runtimeCapabilities.ts';`,
      ].join('\n'),
      resolveDir: runtimeRoot,
      loader: 'ts',
    },
    bundle: true,
    format: 'esm',
    platform: 'browser',
    outfile,
    logLevel: 'silent',
  })
  runtime = await import(pathToFileURL(outfile).href)
})

after(() => {
  if (bundleDir) rmSync(bundleDir, { recursive: true, force: true })
})

const HEX = 'a'.repeat(64)

export const makeIdentity = (overrides = {}) => ({
  publisher_id: 'test-publisher',
  app_id: 'line-crossing',
  publisher_key_sha256: HEX,
  native_tbs_sha256: HEX,
  ui_tbs_sha256: HEX,
  build_id: 'runtime-fixture-build',
  host_boot_generation: 3,
  native_session_generation: 11,
  ui_generation: 1,
  sidecar_service_generation: 2,
  ...overrides,
})

const makeHello = (overrides = {}) => ({
  protocol: 'ne301.sidecar.bridge.v1',
  type: 'HELLO',
  seq: 1,
  grant_id: 'G'.repeat(24),
  identity: makeIdentity(),
  channel: 'ne301.sidecar.bridge.v1',
  ...overrides,
})

const makeGrant = (overrides = {}) => ({
  protocol: 'ne301.sidecar.bridge.v1',
  type: 'GRANT',
  seq: 2,
  grant_id: 'G'.repeat(24),
  identity: makeIdentity(),
  expires_at_ms: Date.now() + 600000,
  ops: ['snapshot.read', 'config.apply'],
  ...overrides,
})

class FakePort {
  constructor() {
    this.sent = []
    this.listeners = []
    this.closed = false
  }

  postMessage(data) {
    this.sent.push(data)
  }

  addEventListener(_type, listener) {
    this.listeners.push(listener)
  }

  removeEventListener(_type, listener) {
    this.listeners = this.listeners.filter(item => item !== listener)
  }

  close() {
    this.closed = true
  }

  start() {}

  emit(data) {
    for (const listener of [...this.listeners]) listener({ data })
  }
}

const connect = (options = {}) => {
  const session = new runtime.BridgeSession(options)
  const port = new FakePort()
  assert.equal(session.acceptHello(makeHello(), port), true)
  return { session, port }
}

const authorized = (grantOverrides = {}, sessionOptions = {}) => {
  const context = connect(sessionOptions)
  context.port.emit(makeGrant({ seq: 2, ...grantOverrides }))
  assert.equal(context.session.getPhase(), 'authorized')
  return context
}

const flushMicrotasks = () => new Promise(resolve => setTimeout(resolve, 0))

test('frozen bridge v1 constants match the cross-repo wire freeze', () => {
  assert.equal(runtime.BRIDGE_PROTOCOL, 'ne301.sidecar.bridge.v1')
  assert.equal(runtime.BRIDGE_CHANNEL, 'ne301.sidecar.bridge.v1')
  assert.equal(runtime.BRIDGE_APP_ID, 'line-crossing')
  assert.deepEqual([...runtime.BRIDGE_OPS], [
    'snapshot.read', 'config.read', 'config.apply', 'counters.reset',
    'report-policy.read', 'report-policy.apply', 'video.open', 'video.close',
    'enable.read', 'enable.apply', 'live.subscribe', 'live.unsubscribe',
  ])
  assert.deepEqual([...runtime.BRIDGE_OUTCOMES], ['APPLIED', 'CONFLICT', 'UNKNOWN', 'REJECTED', 'UNAVAILABLE'])
  assert.equal(runtime.MAX_MESSAGE_BYTES, 16384)
  assert.equal(runtime.MAX_PENDING_REQUESTS, 4)
  assert.equal(runtime.REQUEST_DEADLINE_MS, 10000)
})

test('identity validation is strict about schema, digests and generation counters', () => {
  assert.equal(runtime.validateIdentity(makeIdentity()).ok, true)
  const invalid = [
    ['missing field', identity => { delete identity.build_id }],
    ['extra field', identity => { identity.token = 'x' }],
    ['bad digest', identity => { identity.ui_tbs_sha256 = 'ZZ' }],
    ['negative generation', identity => { identity.ui_generation = -1 }],
    ['float generation', identity => { identity.host_boot_generation = 1.5 }],
    ['non-string app id', identity => { identity.app_id = 7 }],
  ]
  for (const [label, mutate] of invalid) {
    const candidate = makeIdentity()
    mutate(candidate)
    assert.equal(runtime.validateIdentity(candidate).ok, false, label)
  }
  assert.equal(runtime.validateIdentity('identity').ok, false)
  assert.equal(runtime.validateIdentity(null).ok, false)
})

test('envelope validators reject wrong protocol, extra fields, bad enums and non-plain payloads', () => {
  assert.equal(runtime.validateGrant(makeGrant()).ok, true)
  assert.equal(runtime.validateHello(makeHello()).ok, true)
  const result = {
    protocol: 'ne301.sidecar.bridge.v1', type: 'RESULT', seq: 3, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), request_id: 1, op: 'snapshot.read', outcome: 'APPLIED', payload: { ok: true },
  }
  assert.equal(runtime.validateResult(result).ok, true)
  assert.equal(runtime.validateResult({ ...result, outcome: 'MAYBE' }).ok, false)
  assert.equal(runtime.validateResult({ ...result, payload: () => {} }).ok, false)
  assert.equal(runtime.validateResult({ ...result, extra: 1 }).ok, false)
  assert.equal(runtime.validateGrant({ ...makeGrant(), protocol: 'other.v1' }).ok, false)
  assert.equal(runtime.validateGrant({ ...makeGrant(), ops: ['snapshot.read', 'snapshot.read'] }).ok, false)
  assert.equal(runtime.validateGrant({ ...makeGrant(), ops: ['made.up.op'] }).ok, false)
  assert.equal(runtime.validateHello({ ...makeHello(), channel: 'other.channel' }).ok, false)
  assert.equal(runtime.validateHello({ ...makeHello(), seq: -1 }).ok, false)
  assert.equal(runtime.validateHello({ ...makeHello(), seq: 1.5 }).ok, false)
  const event = {
    protocol: 'ne301.sidecar.bridge.v1', type: 'EVENT', seq: 9, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), payload: { stream: 'live', stream_seq: 1, data: { server_now_ms: 1 } },
  }
  assert.equal(runtime.validateEvent(event).ok, true)
  assert.equal(runtime.validateEvent({ ...event, payload: { stream: 'live', stream_seq: 1, status: 'EXPLODED' } }).ok, false)
  const revoke = {
    protocol: 'ne301.sidecar.bridge.v1', type: 'REVOKE', seq: 10, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), reason: 'operator revoked the grant',
  }
  assert.equal(runtime.validateRevoke(revoke).ok, true)
  assert.equal(runtime.validateRevoke({ ...revoke, reason: '' }).ok, false)
})

test('message size accounting enforces the 16 KiB structured-clone bound', () => {
  assert.equal(runtime.withinMessageLimit({ text: 'x'.repeat(16374) }), true)
  assert.equal(runtime.withinMessageLimit({ text: 'x'.repeat(16375) }), false)
  assert.equal(runtime.withinMessageLimit({ list: Array.from({ length: 300 }, () => 1) }), false)
  assert.equal(runtime.withinMessageLimit({ deep: { a: { b: { c: { d: 1 } } } } }), true)
})

test('session ignores duplicate HELLO and refuses requests before authorization without sending', async () => {
  const { session, port } = connect()
  assert.equal(session.acceptHello(makeHello(), new FakePort()), false)
  const outcome = await session.request('snapshot.read')
  assert.equal(outcome.outcome, 'UNAVAILABLE')
  assert.match(outcome.reason, /not authorized/)
  assert.equal(port.sent.length, 0)
})

test('session refuses ops outside the grant whitelist without sending', async () => {
  const { session, port } = authorized({ ops: ['snapshot.read'] })
  const outcome = await session.request('enable.apply', { value: true })
  assert.equal(outcome.outcome, 'UNAVAILABLE')
  assert.match(outcome.reason, /Host has not granted enable\.apply/)
  assert.equal(port.sent.length, 0)
})

test('authorized request emits the exact v1 REQUEST envelope and resolves on the matching RESULT', async () => {
  const { session, port } = authorized()
  const pending = session.request('snapshot.read', { session_generation: 8 })
  await flushMicrotasks()
  assert.equal(port.sent.length, 1)
  const request = port.sent[0]
  assert.equal(request.protocol, 'ne301.sidecar.bridge.v1')
  assert.equal(request.type, 'REQUEST')
  assert.equal(request.seq, 1)
  assert.equal(request.request_id, 1)
  assert.equal(request.op, 'snapshot.read')
  assert.deepEqual(request.payload, { session_generation: 8 })
  assert.equal(request.grant_id, 'G'.repeat(24))
  assert.deepEqual(request.identity, makeIdentity())
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'RESULT', seq: 3, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), request_id: 1, op: 'snapshot.read', outcome: 'APPLIED', payload: { ok: 1 },
  })
  const outcome = await pending
  assert.equal(outcome.outcome, 'APPLIED')
  assert.deepEqual(outcome.payload, { ok: 1 })
})

test('expired requests resolve UNKNOWN and their late RESULTS are ignored without state changes', async () => {
  const { session, port } = authorized({ ops: ['snapshot.read'] }, { deadlineMs: 20 })
  const pending = session.request('snapshot.read')
  await new Promise(resolve => setTimeout(resolve, 60))
  const outcome = await pending
  assert.equal(outcome.outcome, 'UNKNOWN')
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'RESULT', seq: 3, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), request_id: 1, op: 'snapshot.read', outcome: 'APPLIED', payload: { late: true },
  })
  assert.ok(session.getDroppedInboundCount() >= 1)
  const next = session.request('snapshot.read')
  await flushMicrotasks()
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'RESULT', seq: 4, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), request_id: 2, op: 'snapshot.read', outcome: 'APPLIED', payload: { fresh: true },
  })
  const fresh = await next
  assert.equal(fresh.outcome, 'APPLIED')
  assert.deepEqual(fresh.payload, { fresh: true })
})

test('pending request concurrency is capped at four without sending the fifth', async () => {
  const { session, port } = authorized({ ops: ['snapshot.read'] }, { deadlineMs: 200 })
  const outcomes = []
  for (let index = 0; index < 5; index += 1) outcomes.push(session.request('snapshot.read'))
  await flushMicrotasks()
  assert.equal(port.sent.length, 4)
  const fifth = await outcomes[4]
  assert.equal(fifth.outcome, 'UNAVAILABLE')
  assert.match(fifth.reason, /pending request limit/)
  for (let index = 0; index < 4; index += 1) {
    port.emit({
      protocol: 'ne301.sidecar.bridge.v1', type: 'RESULT', seq: 3 + index, grant_id: 'G'.repeat(24),
      identity: makeIdentity(), request_id: index + 1, op: 'snapshot.read', outcome: 'APPLIED', payload: {},
    })
  }
  const settled = await Promise.all(outcomes.slice(0, 4))
  assert.ok(settled.every(outcome => outcome.outcome === 'APPLIED'))
})

test('mismatched request ids and ops are ignored and keep the original pending until timeout', async () => {
  const { session, port } = authorized({ ops: ['snapshot.read'] }, { deadlineMs: 40 })
  const pending = session.request('snapshot.read')
  await flushMicrotasks()
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'RESULT', seq: 3, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), request_id: 99, op: 'snapshot.read', outcome: 'APPLIED', payload: {},
  })
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'RESULT', seq: 4, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), request_id: 1, op: 'config.apply', outcome: 'APPLIED', payload: {},
  })
  const outcome = await pending
  assert.equal(outcome.outcome, 'UNKNOWN')
})

test('replayed sequence numbers are dropped while fresh traffic continues', async () => {
  const { session, port } = authorized({ ops: ['snapshot.read'] })
  const first = session.request('snapshot.read')
  await flushMicrotasks()
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'RESULT', seq: 3, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), request_id: 1, op: 'snapshot.read', outcome: 'APPLIED', payload: { n: 1 },
  })
  assert.equal((await first).outcome, 'APPLIED')
  const droppedBefore = session.getDroppedInboundCount()
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'RESULT', seq: 3, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), request_id: 2, op: 'snapshot.read', outcome: 'APPLIED', payload: { replayed: true },
  })
  assert.equal(session.getDroppedInboundCount(), droppedBefore + 1)
  assert.equal(session.getPhase(), 'authorized')
  const second = session.request('snapshot.read')
  await flushMicrotasks()
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'RESULT', seq: 4, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), request_id: 2, op: 'snapshot.read', outcome: 'APPLIED', payload: { n: 2 },
  })
  const outcome = await second
  assert.deepEqual(outcome.payload, { n: 2 })
})

test('a RESULT from another identity revokes the session, flushes pending and closes the port', async () => {
  const { session, port } = authorized({ ops: ['snapshot.read'] })
  const notifications = []
  session.subscribe(notification => notifications.push(notification))
  const pending = session.request('snapshot.read')
  await flushMicrotasks()
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'RESULT', seq: 3, grant_id: 'G'.repeat(24),
    identity: makeIdentity({ ui_tbs_sha256: 'b'.repeat(64) }), request_id: 1, op: 'snapshot.read',
    outcome: 'APPLIED', payload: {},
  })
  const outcome = await pending
  assert.equal(outcome.outcome, 'UNAVAILABLE')
  assert.match(outcome.reason, /revoked/)
  assert.equal(session.getPhase(), 'revoked')
  assert.equal(port.closed, true)
  assert.ok(notifications.some(notification => notification.kind === 'revoked'))
  const blocked = await session.request('snapshot.read')
  assert.equal(blocked.outcome, 'UNAVAILABLE')
})

test('REVOKE is honored once and a replayed REVOKE stays inert', async () => {
  const { session, port } = authorized()
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'REVOKE', seq: 3, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), reason: 'operator revoked',
  })
  assert.equal(session.getPhase(), 'revoked')
  assert.equal(port.closed, true)
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'REVOKE', seq: 3, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), reason: 'operator revoked',
  })
  assert.equal(session.getPhase(), 'revoked')
  assert.equal(session.getDroppedInboundCount(), 0)
})

test('a GRANT whose identity deviates from the handshake revokes the session', () => {
  const { session, port } = connect()
  port.emit(makeGrant({ identity: makeIdentity({ app_id: 'other-app' }) }))
  assert.equal(session.getPhase(), 'revoked')
})

test('grant refresh with the same identity updates expiry and ops without breaking the session', async () => {
  const { session, port } = authorized({ ops: ['snapshot.read'], expires_at_ms: Date.now() + 1000 })
  const notifications = []
  session.subscribe(notification => notifications.push(notification))
  port.emit(makeGrant({ seq: 3, ops: ['snapshot.read', 'config.apply'], expires_at_ms: Date.now() + 900000 }))
  assert.equal(session.getPhase(), 'authorized')
  assert.deepEqual(session.getGrant().ops, ['snapshot.read', 'config.apply'])
  assert.equal(notifications.filter(notification => notification.kind === 'grant').length, 1)
})

test('an already-expired GRANT never authorizes a request', async () => {
  const clock = { now: 100 }
  const { session, port } = connect({ nowFn: () => clock.now })
  port.emit(makeGrant({
    seq: 2,
    expires_at_ms: 99,
    ops: ['snapshot.read', 'config.apply'],
  }))

  const outcome = await session.request('config.apply', { candidate: { counter_name: 'Expired' } })
  assert.equal(outcome.outcome, 'UNAVAILABLE')
  assert.equal(port.sent.length, 0)
  assert.equal(session.getPhase(), 'awaiting-grant')
  assert.equal(session.getGrant(), null)
})

test('a REQUEST whose grant expires before transport send is refused unsent', async () => {
  const clock = { now: 100 }
  const { session, port } = connect({ nowFn: () => clock.now })
  port.emit(makeGrant({ seq: 2, expires_at_ms: 110, ops: ['config.apply'] }))
  const payload = {}
  Object.defineProperty(payload, 'candidate', {
    enumerable: true,
    get: () => {
      clock.now = 110
      return { counter_name: 'Expired while preparing request' }
    },
  })

  const outcome = await session.request('config.apply', payload)
  assert.equal(outcome.outcome, 'UNAVAILABLE')
  assert.equal(port.sent.length, 0)
  assert.equal(session.getGrant(), null)
})

test('a RESULT processed at GRANT expiry resolves UNKNOWN instead of APPLIED', async () => {
  const clock = { now: 100 }
  const { session, port } = connect({ nowFn: () => clock.now })
  port.emit(makeGrant({ seq: 2, expires_at_ms: 110, ops: ['snapshot.read', 'config.apply'] }))
  const pending = session.request('config.apply', { candidate: { counter_name: 'At expiry' } })
  await flushMicrotasks()
  assert.equal(port.sent.length, 1)

  clock.now = 110
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'RESULT', seq: 3, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), request_id: 1, op: 'config.apply', outcome: 'APPLIED',
    payload: { session_generation: 8, config_generation: 13 },
  })

  const outcome = await pending
  assert.equal(outcome.outcome, 'UNKNOWN')
  assert.equal(session.getPhase(), 'awaiting-grant')
  assert.equal(session.getGrant(), null)
})

test('an EVENT processed at GRANT expiry is dropped before it reaches subscribers', () => {
  const clock = { now: 100 }
  const { session, port } = connect({ nowFn: () => clock.now })
  port.emit(makeGrant({ seq: 2, expires_at_ms: 110, ops: ['snapshot.read'] }))
  const notifications = []
  session.subscribe(notification => notifications.push(notification))

  clock.now = 110
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'EVENT', seq: 3, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), payload: { stream: 'live', stream_seq: 1, data: { server_now_ms: 5 } },
  })

  assert.equal(notifications.some(notification => notification.kind === 'event'), false)
  assert.equal(session.getPhase(), 'awaiting-grant')
  assert.equal(session.getGrant(), null)
})

test('a fresh same-identity GRANT restores authorization while stale seq and changed identity stay rejected', async () => {
  const clock = { now: 100 }
  const { session, port } = connect({ nowFn: () => clock.now })
  port.emit(makeGrant({ seq: 2, expires_at_ms: 110, ops: ['snapshot.read'] }))

  clock.now = 110
  const expiredRequest = await session.request('snapshot.read')
  assert.equal(expiredRequest.outcome, 'UNAVAILABLE')
  assert.equal(session.getPhase(), 'awaiting-grant')

  port.emit(makeGrant({ seq: 3, expires_at_ms: 200, ops: ['snapshot.read', 'config.apply'] }))
  assert.equal(session.getPhase(), 'authorized')
  const sentBefore = port.sent.length
  const refreshedRequest = session.request('config.apply')
  await flushMicrotasks()
  assert.equal(port.sent.length, sentBefore + 1)

  port.emit(makeGrant({ seq: 2, expires_at_ms: 300, ops: ['snapshot.read'] }))
  assert.equal(session.getPhase(), 'authorized')
  assert.deepEqual(session.getGrant().ops, ['snapshot.read', 'config.apply'])

  port.emit(makeGrant({ seq: 4, identity: makeIdentity({ ui_tbs_sha256: 'b'.repeat(64) }), expires_at_ms: 300 }))
  assert.equal(session.getPhase(), 'revoked')
  assert.equal(session.getGrant(), null)
  assert.equal((await session.request('snapshot.read')).outcome, 'UNAVAILABLE')
  assert.equal(port.sent.length, sentBefore + 1)
  port.close()
  await refreshedRequest
})

test('oversized inbound messages revoke the session; oversized outbound requests are refused unsent', async () => {
  const oversized = authorized({ ops: ['snapshot.read'] })
  oversized.port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'RESULT', seq: 3, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), request_id: 1, op: 'snapshot.read', outcome: 'APPLIED',
    payload: { blob: 'x'.repeat(20000) },
  })
  assert.equal(oversized.session.getPhase(), 'revoked')

  const { session, port } = authorized({ ops: ['config.apply'] })
  const outcome = await session.request('config.apply', { candidate: { blob: 'x'.repeat(20000) } })
  assert.equal(outcome.outcome, 'UNAVAILABLE')
  assert.match(outcome.reason, /size limit/)
  assert.equal(port.sent.length, 0)
})

test('valid EVENT notifications flow while malformed EVENTs revoke the session', () => {
  const { session, port } = authorized()
  const notifications = []
  session.subscribe(notification => notifications.push(notification))
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'EVENT', seq: 3, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), payload: { stream: 'live', stream_seq: 1, data: { server_now_ms: 5 } },
  })
  assert.equal(notifications.at(-1).kind, 'event')
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'EVENT', seq: 4, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), payload: { stream: 'live', stream_seq: 2, unexpected: true },
  })
  assert.equal(session.getPhase(), 'revoked')
})

test('inbound traffic before the GRANT is dropped without breaking the handshake', () => {
  const { session, port } = connect()
  port.emit({
    protocol: 'ne301.sidecar.bridge.v1', type: 'RESULT', seq: 5, grant_id: 'G'.repeat(24),
    identity: makeIdentity(), request_id: 1, op: 'snapshot.read', outcome: 'APPLIED', payload: {},
  })
  assert.equal(session.getPhase(), 'awaiting-grant')
  assert.ok(session.getDroppedInboundCount() >= 1)
  port.emit(makeGrant({ seq: 6 }))
  assert.equal(session.getPhase(), 'authorized')
})

const stubSession = () => {
  const subscribers = new Set()
  const stub = {
    phase: 'awaiting-hello',
    requests: [],
    responder: () => ({ outcome: 'UNAVAILABLE', reason: 'stub has no responder' }),
    getPhase: () => stub.phase,
    getIdentity: () => null,
    revoke() {},
    subscribe(listener) {
      subscribers.add(listener)
      return () => subscribers.delete(listener)
    },
    async request(op, payload) {
      stub.requests.push({ op, payload })
      const outcome = stub.responder(op, payload)
      const payloadReason = outcome.payload && typeof outcome.payload === 'object' ? outcome.payload.reason : undefined
      return { ...outcome, reason: outcome.reason ?? (typeof payloadReason === 'string' ? payloadReason : undefined) }
    },
    emit(notification) {
      for (const listener of [...subscribers]) listener(notification)
    },
  }
  return stub
}

const GRANT_OPS = [
  'snapshot.read', 'config.apply', 'counters.reset', 'report-policy.read',
  'report-policy.apply', 'video.open', 'video.close', 'enable.read', 'enable.apply',
]

const bridgeSnapshot = (overrides = {}) => ({
  session_generation: 8,
  config_generation: 12,
  config: {
    schema: 1,
    counter_name: 'Counter Bridge',
    target_class_name: 'person',
    line: { x1: 250, y1: 500, x2: 750, y2: 500, outside_x: 500, outside_y: 350 },
    conf_threshold_permille: 550,
    max_dist_permille: 350,
    track_history_k: 8,
    max_miss: 12,
    k_confirm: 2,
    tracks_report_enable: true,
    heat_grid_enable: false,
    window_minutes: 60,
  },
  status: {
    state: 'running',
    target_class: 'person',
    model: {
      name: 'Bridge Model',
      version: 'fixture',
      postprocess_type: 'yolo',
      generation: 3,
      classes: [{ id: 0, name: 'person' }],
    },
  },
  stats: { window: { in: 5, out: 2 }, total: { in: 50, out: 20 } },
  ...overrides,
})

const makeController = (responder, grantOverrides = {}) => {
  const session = stubSession()
  session.responder = responder
  const controller = runtime.createRuntimeController(session, { pollIntervalMs: 0 })
  session.phase = 'authorized'
  session.emit({
    kind: 'grant',
    grant: makeGrant({ seq: 2, ops: GRANT_OPS, expires_at_ms: Date.now() + 600000, ...grantOverrides }),
  })
  return { session, controller }
}

const settleUntil = async (predicate, timeoutMs = 2000) => {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return true
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  return false
}

const waitAuthored = async controller =>
  settleUntil(() => controller.getState().app.state === 'available')

const capabilityStates = state => [
  state.app, state.configWrite, state.businessEnable, state.enableWrite, state.stats,
  state.events, state.tracks, state.statsReset, state.hostPolicy, state.hostPolicyWrite, state.video,
]

test('unauthorized runtime controller keeps every capability unavailable without fabricating values', async () => {
  const session = stubSession()
  const controller = runtime.createRuntimeController(session, { pollIntervalMs: 0 })
  const state = await controller.refresh()
  assert.ok(capabilityStates(state).every(capability => capability.state === 'unavailable'))
  assert.match(state.app.reason, /not authorized/)
  assert.equal(state.revision, 1)
  assert.equal(session.requests.length, 0)
})

test('an authorized grant maps snapshot, policy and whitelist capabilities; absent producers stay unavailable', async () => {
  const { controller } = makeController(op => {
    if (op === 'snapshot.read') return { outcome: 'APPLIED', payload: bridgeSnapshot() }
    if (op === 'report-policy.read') {
      return {
        outcome: 'APPLIED',
        payload: { session_generation: 8, generation: 4, config: { mqtt_enabled: false, webhook_enabled: true, backlog_capacity: 32 } },
      }
    }
    if (op === 'enable.read') return { outcome: 'UNAVAILABLE', payload: { reason: 'Enable producer is not implemented' } }
    return { outcome: 'UNAVAILABLE' }
  })
  assert.equal(await waitAuthored(controller), true)
  const state = controller.getState()
  assert.equal(state.app.state, 'available')
  assert.equal(state.app.value.sessionGeneration, 8)
  assert.equal(state.app.value.configGeneration, 12)
  assert.equal(state.app.value.config.counter_name, 'Counter Bridge')
  assert.equal(state.app.value.status.state, 'running')
  assert.equal(state.stats.state, 'available')
  assert.deepEqual([state.stats.value.window.in, state.stats.value.total.out], [5, 20])
  assert.equal(state.hostPolicy.value.generation, 4)
  assert.equal(state.hostPolicy.value.sessionGeneration, 8)
  assert.ok(state.hostPolicy.value.observedAtMs > 0)
  assert.equal(state.hostPolicy.value.config.backlog_capacity, 32)
  assert.equal(state.configWrite.value, true)
  assert.equal(state.statsReset.value, true)
  assert.equal(state.hostPolicyWrite.value, true)
  assert.equal(state.enableWrite.value, true)
  assert.equal(state.businessEnable.state, 'unavailable')
  assert.match(state.businessEnable.reason, /enable\.read unavailable/)
  assert.match(state.businessEnable.reason, /Enable producer is not implemented/)
  assert.equal(state.events.state, 'unavailable')
  assert.match(state.events.reason, /live\.subscribe/)
  assert.equal(state.tracks.state, 'unavailable')
})

test('malformed snapshot payloads fail closed instead of partially filling the UI', async () => {
  const broken = bridgeSnapshot()
  broken.config.conf_threshold_permille = 5000
  const { controller } = makeController(op => (op === 'snapshot.read' ? { outcome: 'APPLIED', payload: broken } : { outcome: 'UNAVAILABLE' }))
  assert.equal(await settleUntil(() => controller.getState().app.state === 'unavailable' && /failed validation/.test(controller.getState().app.reason || '')), true)
  const state = controller.getState()
  assert.equal(state.stats.state, 'unavailable')
  assert.equal(state.events.state, 'unavailable')
})

test('a snapshot without statistics leaves stats honestly unavailable', async () => {
  const snapshot = bridgeSnapshot()
  delete snapshot.stats
  const { controller } = makeController(op => (op === 'snapshot.read' ? { outcome: 'APPLIED', payload: snapshot } : { outcome: 'UNAVAILABLE' }))
  assert.equal(await waitAuthored(controller), true)
  const state = controller.getState()
  assert.equal(state.stats.state, 'unavailable')
  assert.match(state.stats.reason, /did not include statistics/)
})

test('config.apply commits only generation-consistent APPLIED results', async () => {
  const applied = (configGeneration, sessionGeneration = 8) => ({
    outcome: 'APPLIED',
    payload: {
      session_generation: sessionGeneration,
      config_generation: configGeneration,
      snapshot: bridgeSnapshot({ config_generation: configGeneration, session_generation: sessionGeneration, config: { ...bridgeSnapshot().config, counter_name: 'Renamed' } }),
    },
  })
  const happy = makeController(op => {
    if (op === 'snapshot.read') return { outcome: 'APPLIED', payload: bridgeSnapshot() }
    if (op === 'config.apply') return applied(13)
    return { outcome: 'UNAVAILABLE' }
  })
  await waitAuthored(happy.controller)
  const outcome = await happy.controller.capabilities.applyConfig({
    sessionGeneration: 8,
    expectedConfigGeneration: 12,
    candidate: bridgeSnapshot().config,
  })
  assert.equal(outcome.outcome, 'APPLIED')
  assert.equal(outcome.configGeneration, 13)
  assert.equal(happy.controller.getState().app.value.configGeneration, 13)
  assert.equal(happy.controller.getState().app.value.config.counter_name, 'Renamed')

  const stale = makeController(op => {
    if (op === 'snapshot.read') return { outcome: 'APPLIED', payload: bridgeSnapshot() }
    if (op === 'config.apply') return applied(12)
    return { outcome: 'UNAVAILABLE' }
  })
  await waitAuthored(stale.controller)
  const staleOutcome = await stale.controller.capabilities.applyConfig({
    sessionGeneration: 8,
    expectedConfigGeneration: 12,
    candidate: bridgeSnapshot().config,
  })
  assert.equal(staleOutcome.outcome, 'UNKNOWN')
  assert.match(staleOutcome.reason, /generation cross-check/)
  assert.equal(stale.controller.getState().app.value.configGeneration, 12)
  assert.equal(stale.controller.getState().app.value.config.counter_name, 'Counter Bridge')

  const foreignSession = makeController(op => {
    if (op === 'snapshot.read') return { outcome: 'APPLIED', payload: bridgeSnapshot() }
    if (op === 'config.apply') return applied(13, 99)
    return { outcome: 'UNAVAILABLE' }
  })
  await waitAuthored(foreignSession.controller)
  const foreignOutcome = await foreignSession.controller.capabilities.applyConfig({
    sessionGeneration: 8,
    expectedConfigGeneration: 12,
    candidate: bridgeSnapshot().config,
  })
  assert.equal(foreignOutcome.outcome, 'UNKNOWN')

  const rejected = makeController(op => {
    if (op === 'snapshot.read') return { outcome: 'APPLIED', payload: bridgeSnapshot() }
    if (op === 'config.apply') return { outcome: 'REJECTED', payload: { reason: 'Host refused the write' } }
    return { outcome: 'UNAVAILABLE' }
  })
  await waitAuthored(rejected.controller)
  const rejectedOutcome = await rejected.controller.capabilities.applyConfig({
    sessionGeneration: 8,
    expectedConfigGeneration: 12,
    candidate: bridgeSnapshot().config,
  })
  assert.equal(rejectedOutcome.outcome, 'UNAVAILABLE')
  assert.match(rejectedOutcome.reason, /rejected config\.apply/)
})

test('setBusinessEnable consumes only cross-checked APPLIED outcomes of the current session', async () => {
  const grant = { ops: [...GRANT_OPS, 'live.subscribe'] }
  const enableResult = { outcome: 'APPLIED', payload: { session_generation: 8, value: true } }
  const happy = makeController(op => {
    if (op === 'snapshot.read') return { outcome: 'APPLIED', payload: bridgeSnapshot() }
    if (op === 'enable.read') return { outcome: 'APPLIED', payload: { session_generation: 8, value: false } }
    if (op === 'enable.apply') return enableResult
    return { outcome: 'UNAVAILABLE' }
  }, grant)
  await waitAuthored(happy.controller)
  const outcome = await happy.controller.capabilities.setBusinessEnable({ sessionGeneration: 8, value: true })
  assert.equal(outcome.outcome, 'APPLIED')
  assert.equal(happy.controller.getState().businessEnable.state, 'available')
  assert.equal(happy.controller.getState().businessEnable.value, true)

  const mismatch = makeController(op => {
    if (op === 'snapshot.read') return { outcome: 'APPLIED', payload: bridgeSnapshot() }
    if (op === 'enable.apply') return { outcome: 'APPLIED', payload: { session_generation: 8, value: false } }
    return { outcome: 'UNAVAILABLE' }
  }, grant)
  await waitAuthored(mismatch.controller)
  const mismatchOutcome = await mismatch.controller.capabilities.setBusinessEnable({ sessionGeneration: 8, value: true })
  assert.equal(mismatchOutcome.outcome, 'UNKNOWN')
})

test('resetStats re-reads the authoritative snapshot after an APPLIED reset', async () => {
  let reset = false
  const { controller } = makeController(op => {
    if (op === 'snapshot.read') {
      return { outcome: 'APPLIED', payload: bridgeSnapshot({ stats: reset ? { window: { in: 0, out: 0 }, total: { in: 0, out: 0 } } : { window: { in: 5, out: 2 }, total: { in: 50, out: 20 } } }) }
    }
    if (op === 'counters.reset') {
      reset = true
      return { outcome: 'APPLIED', payload: { session_generation: 8 } }
    }
    return { outcome: 'UNAVAILABLE' }
  })
  await waitAuthored(controller)
  const outcome = await controller.capabilities.resetStats({ sessionGeneration: 8 })
  assert.equal(outcome.outcome, 'APPLIED')
  assert.equal(controller.getState().stats.value.total.in, 0)
})

test('openVideoStream validates scheme, session and expiry; release stops the media session', async () => {
  const videoPayload = overrides => ({
    outcome: 'APPLIED',
    payload: { url: 'ws://media.example/stream?token=abc', session_generation: 8, expires_at_ms: Date.now() + 60000, grant_id: 'G'.repeat(24), ...overrides },
  })
  const happy = makeController(op => {
    if (op === 'snapshot.read') return { outcome: 'APPLIED', payload: bridgeSnapshot() }
    if (op === 'video.open') return videoPayload()
    return { outcome: 'UNAVAILABLE' }
  })
  await waitAuthored(happy.controller)
  const grant = await happy.controller.capabilities.openVideoStream({ sessionGeneration: 8 })
  assert.equal(grant.state, 'available')
  grant.value.release()
  grant.value.release()
  assert.ok(happy.session.requests.some(request => request.op === 'video.close' && request.payload.grant_id === 'G'.repeat(24)))
  assert.equal(happy.session.requests.filter(request => request.op === 'video.close').length, 1)

  const plainHttp = makeController(op => {
    if (op === 'snapshot.read') return { outcome: 'APPLIED', payload: bridgeSnapshot() }
    if (op === 'video.open') return videoPayload({ url: 'http://media.example/stream' })
    return { outcome: 'UNAVAILABLE' }
  })
  await waitAuthored(plainHttp.controller)
  const refused = await plainHttp.controller.capabilities.openVideoStream({ sessionGeneration: 8 })
  assert.equal(refused.state, 'unavailable')
  assert.match(refused.reason, /media websocket/)

  const expired = makeController(op => {
    if (op === 'snapshot.read') return { outcome: 'APPLIED', payload: bridgeSnapshot() }
    if (op === 'video.open') return videoPayload({ expires_at_ms: Date.now() - 1 })
    return { outcome: 'UNAVAILABLE' }
  })
  await waitAuthored(expired.controller)
  const expiredGrant = await expired.controller.capabilities.openVideoStream({ sessionGeneration: 8 })
  assert.match(expiredGrant.reason, /cross-check/)
})

test('live subscription delivers bounded EVENT data and accepts replayed sequence as resync', async () => {
  const liveEvent = {
    kind: 'event',
    event: {
      payload: {
        stream: 'live',
        stream_seq: 1,
        data: {
          server_now_ms: Date.now(),
          events: [{ sequence: 7, timestamp_ms: Date.now() - 1000, track_id: 12, direction: 'in', target_class: 'person' }],
          tracks: [{ track_id: 12, points: [{ x: 200, y: 500 }, { x: 400, y: 500 }] }],
        },
      },
    },
  }
  const { session, controller } = makeController(op => (op === 'live.subscribe' ? { outcome: 'APPLIED', payload: {} } : { outcome: 'UNAVAILABLE' }), {
    ops: [...GRANT_OPS, 'live.subscribe'],
  })
  assert.equal(await settleUntil(() => controller.getState().events.state === 'unavailable'), true)
  assert.match(controller.getState().events.reason, /not been received/)
  session.emit(liveEvent)
  assert.equal(await settleUntil(() => controller.getState().events.state === 'available'), true)
  assert.equal(controller.getState().tracks.state, 'available')
  assert.equal(controller.getState().events.value.events.length, 1)
  session.emit({ kind: 'event', event: { payload: { stream: 'live', stream_seq: 1, data: liveEvent.event.payload.data } } })
  await flushMicrotasks()
  assert.equal(controller.getState().events.state, 'available')
  assert.equal(controller.getState().events.value.events.length, 1)
})

test('STALE and GAP notifications are transient and later frames resync the live view', async () => {
  const frame = seq => ({
    kind: 'event',
    event: {
      payload: {
        stream: 'live',
        stream_seq: seq,
        data: {
          server_now_ms: Date.now(),
          events: [{ sequence: seq, timestamp_ms: Date.now() - 1000, track_id: 12, direction: 'in', target_class: 'person' }],
          tracks: [{ track_id: 12, points: [{ x: seq * 100, y: 500 }] }],
        },
      },
    },
  })
  const status = (name, seq) => ({ kind: 'event', event: { payload: { stream: 'live', stream_seq: seq, status: name } } })
  const { session, controller } = makeController(op => (op === 'live.subscribe' ? { outcome: 'APPLIED', payload: {} } : { outcome: 'UNAVAILABLE' }), {
    ops: [...GRANT_OPS, 'live.subscribe'],
  })
  assert.equal(await settleUntil(() => controller.getState().events.state === 'unavailable'), true)
  session.emit(frame(1))
  assert.equal(await settleUntil(() => controller.getState().events.state === 'available'), true)
  const before = controller.getState().events.value.events
  session.emit(status('STALE', 1))
  session.emit(status('GAP', 1))
  await flushMicrotasks()
  const retained = controller.getState()
  assert.equal(retained.events.state, 'available')
  assert.equal(retained.events.value.events, before)
  assert.equal(retained.tracks.state, 'available')
  session.emit({ kind: 'event', event: { payload: { stream: 'live', stream_seq: 1, data: frame(1).event.payload.data } } })
  await flushMicrotasks()
  assert.equal(controller.getState().events.state, 'available')
  session.emit(frame(2))
  assert.equal(await settleUntil(() => controller.getState().events.value.events[0].sequence === 2), true)
  assert.equal(controller.getState().events.state, 'available')
  assert.equal(controller.getState().tracks.state, 'available')
  session.emit(status('REVOKE', 2))
  assert.equal(await settleUntil(() => controller.getState().events.state === 'unavailable'), true)
  assert.match(controller.getState().events.reason, /revoked/)
  session.emit(frame(3))
  await flushMicrotasks()
  assert.equal(controller.getState().events.state, 'unavailable')
})

test('a missing live producer keeps events and tracks unavailable with the real reason', async () => {
  const { controller } = makeController(op => (op === 'live.subscribe' ? { outcome: 'UNAVAILABLE', payload: { reason: 'live producer is not implemented' } } : { outcome: 'UNAVAILABLE' }), {
    ops: [...GRANT_OPS, 'live.subscribe'],
  })
  assert.equal(await settleUntil(() => /live\.subscribe unavailable/.test(controller.getState().events.reason || '')), true)
  assert.match(controller.getState().events.reason, /live producer is not implemented/)
  assert.equal(controller.getState().tracks.state, 'unavailable')
})

test('revocation clears every capability and blocks subsequent writes', async () => {
  const { session, controller } = makeController(op => (op === 'snapshot.read' ? { outcome: 'APPLIED', payload: bridgeSnapshot() } : { outcome: 'UNAVAILABLE' }))
  await waitAuthored(controller)
  session.emit({ kind: 'revoked', reason: 'operator revoked' })
  assert.equal(await settleUntil(() => controller.getState().video.state === 'unavailable' && /revoked/.test(controller.getState().app.reason || '')), true)
  const outcome = await controller.capabilities.applyConfig({ sessionGeneration: 8, expectedConfigGeneration: 12, candidate: bridgeSnapshot().config })
  assert.equal(outcome.outcome, 'UNAVAILABLE')
})

test('grant expiry notification clears stale capabilities and prevents direct writes', async () => {
  const { session, controller } = makeController(op => (op === 'snapshot.read' ? { outcome: 'APPLIED', payload: bridgeSnapshot() } : { outcome: 'UNAVAILABLE' }))
  await waitAuthored(controller)
  session.emit({ kind: 'grant-expired', reason: 'Bridge grant has expired' })

  const state = controller.getState()
  assert.ok(capabilityStates(state).every(capability => capability.state === 'unavailable'))
  assert.match(state.app.reason, /grant has expired/)
  const outcome = await controller.capabilities.applyConfig({
    sessionGeneration: 8,
    expectedConfigGeneration: 12,
    candidate: bridgeSnapshot().config,
  })
  assert.equal(outcome.outcome, 'UNAVAILABLE')
  assert.equal(session.requests.some(request => request.op === 'config.apply'), false)
})

test('an expired grant stops fetches and marks capabilities unavailable', async () => {
  const { controller, session } = makeController(() => ({ outcome: 'APPLIED', payload: bridgeSnapshot() }), {
    expires_at_ms: Date.now() - 1,
  })
  await settleUntil(() => session.requests.length === 3)
  await new Promise(resolve => setTimeout(resolve, 20))
  const state = await controller.refresh()
  assert.match(state.app.reason, /grant has expired/)
})

test('runtime controller subscription pushes revision-monotonic state to UI listeners', async () => {
  const { controller } = makeController(op => (op === 'snapshot.read' ? { outcome: 'APPLIED', payload: bridgeSnapshot() } : { outcome: 'UNAVAILABLE' }))
  const seen = []
  controller.capabilities.subscribe(state => seen.push(state))
  assert.equal(await waitAuthored(controller), true)
  assert.ok(seen.length >= 1)
  assert.ok(seen.every((state, index) => index === 0 || state.revision > seen[index - 1].revision))
})

test('production entry owns the runtime adapter and test fixtures stay isolated', async () => {
  const { readFileSync, readdirSync } = await import('node:fs')
  const main = readFileSync(path.join(appSourceRoot, 'main.tsx'), 'utf8')
  assert.match(main, /createRuntimeCapabilities/)
  assert.match(main, /connectHostBridge/)
  assert.doesNotMatch(main, /__lineCrossingTest|createTestCapabilities/)
  const collect = directory => readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const file = path.join(directory, entry.name)
    return entry.isDirectory() ? collect(file) : [file]
  })
  const runtimeSources = collect(runtimeRoot).map(file => ({ file, text: readFileSync(file, 'utf8') }))
  for (const { file, text } of runtimeSources) {
    for (const forbidden of ['localStorage', 'document.cookie', 'XMLHttpRequest', 'indexedDB']) {
      assert.equal(text.includes(forbidden), false, `${file} references ${forbidden}`)
    }
  }
  for (const { file, text } of runtimeSources) {
    assert.equal(text.includes('../..'), false, `${file} reaches outside the app source root`)
  }
  const testMain = readFileSync(path.join(repoRoot, 'tests/line-crossing-ui/src/test-main.tsx'), 'utf8')
  assert.match(testMain, /createTestCapabilities/)
})
