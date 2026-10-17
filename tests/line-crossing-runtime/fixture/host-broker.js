const PROTOCOL = 'ne301.sidecar.bridge.v1'
const params = new URLSearchParams(window.location.search)
const IDENTITY = JSON.parse(params.get('identity') || 'null')
const ALL_OPS = [
  'snapshot.read', 'config.read', 'config.apply', 'counters.reset',
  'report-policy.read', 'report-policy.apply', 'video.open', 'video.close',
  'enable.read', 'enable.apply', 'live.subscribe', 'live.unsubscribe',
]
const appOrigin = params.get('app')
const scenario = params.get('scenario') || 'normal'
const enableMode = params.get('enable') || 'unavailable'
const liveMode = params.get('live') || 'unavailable'
const attackOn = (params.get('attack') || 'on') === 'on'
const opaque = scenario === 'opaque'

window.localStorage.setItem('host-admin-fixture', 'fixture-secret')

const appFrame = document.getElementById('appFrame')
const attackFrame = document.getElementById('attackFrame')
if (opaque) appFrame.setAttribute('sandbox', 'allow-scripts')

const grantId = Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join('')

const state = {
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
      name: 'Bridge Fixture Model',
      version: 'fixture',
      postprocess_type: 'yolo',
      generation: 3,
      classes: [{ id: 0, name: 'person' }, { id: 1, name: 'bicycle' }],
    },
  },
  stats: { window: { in: 5, out: 2 }, total: { in: 50, out: 20 } },
  host_generation: 4,
  host_config: { mqtt_enabled: false, webhook_enabled: true, backlog_capacity: 32 },
  enable: enableMode === 'available' ? false : null,
}

const mode = {
  holdGrant: scenario === 'noGrant',
  wrongApp: scenario === 'wrongApp',
  holdNextOp: null,
  seqRollbackNext: false,
  oversizeNext: false,
  staleSessionEchoNext: false,
  respondConflictNext: false,
  respondUnknownNext: false,
}
const control = []
let brokerPort = null
let outboundSeq = 0
let streamSeq = 0
let liveTimer = null
const received = []
const pending = []
const nextSeq = () => { outboundSeq += 1; return outboundSeq }

const snapshotPayload = () => ({
  session_generation: state.session_generation,
  config_generation: state.config_generation,
  config: JSON.parse(JSON.stringify(state.config)),
  status: state.status,
  stats: JSON.parse(JSON.stringify(state.stats)),
})

const grantOps = () => {
  if (scenario === 'limited') {
    return ['snapshot.read', 'report-policy.read', 'report-policy.apply', 'video.open', 'video.close', 'enable.read', 'enable.apply']
  }
  const ops = ALL_OPS.filter(op => op !== 'live.subscribe' && op !== 'live.unsubscribe')
  if (liveMode === 'active' || liveMode === 'producer_missing') ops.push('live.subscribe', 'live.unsubscribe')
  return ops
}

const sendGrant = (overrides = {}) => {
  brokerPort.postMessage({
    protocol: PROTOCOL,
    type: 'GRANT',
    seq: nextSeq(),
    grant_id: grantId,
    identity: mode.wrongApp ? { ...IDENTITY, app_id: 'other-app' } : IDENTITY,
    expires_at_ms: Date.now() + 600000,
    ops: grantOps(),
    ...overrides,
  })
}

const sendResult = result => { brokerPort.postMessage(result) }

const makeEvent = sequence => ({
  sequence,
  timestamp_ms: Date.now() - 1000,
  track_id: 24,
  direction: 'in',
  target_class: 'person',
})
const makeTrack = () => ({ track_id: 24, points: [{ x: 200, y: 500 }, { x: 320, y: 500 }, { x: 440, y: 500 }] })

const startLiveStream = () => {
  if (liveMode !== 'active' || liveTimer !== null) return
  liveTimer = setInterval(() => {
    streamSeq += 1
    brokerPort.postMessage({
      protocol: PROTOCOL,
      type: 'EVENT',
      seq: nextSeq(),
      grant_id: grantId,
      identity: IDENTITY,
      payload: {
        stream: 'live',
        stream_seq: streamSeq,
        data: { server_now_ms: Date.now(), events: [makeEvent(streamSeq)], tracks: [makeTrack()] },
      },
    })
  }, 400)
}

const stopLiveStream = () => {
  if (liveTimer !== null) clearInterval(liveTimer)
  liveTimer = null
}

const respond = (request, outcome, payload) => {
  const base = {
    protocol: PROTOCOL,
    type: 'RESULT',
    grant_id: grantId,
    identity: IDENTITY,
    request_id: request.request_id,
    op: request.op,
    outcome,
    payload,
  }
  if (mode.seqRollbackNext) {
    mode.seqRollbackNext = false
    sendResult({ ...base, seq: outboundSeq })
  }
  sendResult({ ...base, seq: nextSeq() })
}

const handleRequest = request => {
  if (request.type !== 'REQUEST') return
  received.push({ op: request.op, payload: JSON.parse(JSON.stringify(request.payload ?? {})) })
  if (mode.holdNextOp === request.op) {
    mode.holdNextOp = null
    pending.push(request)
    return
  }
  if (mode.oversizeNext) {
    mode.oversizeNext = false
    respond(request, 'APPLIED', { blob: 'x'.repeat(20000) })
    return
  }
  if (mode.respondUnknownNext) {
    mode.respondUnknownNext = false
    respond(request, 'UNKNOWN', { reason: 'fixture unknown result' })
    return
  }
  if (mode.respondConflictNext) {
    mode.respondConflictNext = false
    respond(request, 'CONFLICT', { reason: 'fixture generation conflict' })
    return
  }
  const payload = request.payload || {}
  switch (request.op) {
    case 'snapshot.read':
      respond(request, 'APPLIED', snapshotPayload())
      return
    case 'config.apply': {
      if (mode.staleSessionEchoNext) {
        mode.staleSessionEchoNext = false
        respond(request, 'APPLIED', {
          session_generation: 99,
          config_generation: state.config_generation + 1,
          snapshot: { ...snapshotPayload(), session_generation: 99, config_generation: state.config_generation + 1 },
        })
        return
      }
      state.config_generation += 1
      state.config = JSON.parse(JSON.stringify(payload.candidate))
      respond(request, 'APPLIED', {
        session_generation: state.session_generation,
        config_generation: state.config_generation,
        snapshot: snapshotPayload(),
      })
      return
    }
    case 'counters.reset':
      state.stats = { window: { in: 0, out: 0 }, total: { in: 0, out: 0 } }
      respond(request, 'APPLIED', { session_generation: state.session_generation })
      return
    case 'report-policy.read':
      respond(request, 'APPLIED', { session_generation: state.session_generation, generation: state.host_generation, config: { ...state.host_config } })
      return
    case 'report-policy.apply':
      state.host_generation += 1
      state.host_config = JSON.parse(JSON.stringify(payload.candidate))
      respond(request, 'APPLIED', {
        session_generation: state.session_generation,
        generation: state.host_generation,
        snapshot: { session_generation: state.session_generation, generation: state.host_generation, config: { ...state.host_config } },
      })
      return
    case 'enable.read':
      if (state.enable === null) respond(request, 'UNAVAILABLE', { reason: 'Enable producer is not implemented' })
      else respond(request, 'APPLIED', { session_generation: state.session_generation, value: state.enable })
      return
    case 'enable.apply':
      state.enable = payload.value
      respond(request, 'APPLIED', { session_generation: state.session_generation, value: payload.value })
      return
    case 'video.open':
      if (liveMode === 'producer_missing') {
        respond(request, 'UNAVAILABLE', { reason: 'video producer is not implemented' })
        return
      }
      respond(request, 'APPLIED', {
        url: appOrigin.replace(/^http/, 'ws') + '/stream?grant=' + grantId,
        session_generation: state.session_generation,
        expires_at_ms: Date.now() + 120000,
        grant_id: grantId,
      })
      return
    case 'video.close':
      respond(request, 'APPLIED', { session_generation: payload.session_generation })
      return
    case 'live.subscribe':
      if (liveMode === 'producer_missing') {
        respond(request, 'UNAVAILABLE', { reason: 'live producer is not implemented' })
        return
      }
      respond(request, 'APPLIED', {})
      startLiveStream()
      return
    case 'live.unsubscribe':
      stopLiveStream()
      respond(request, 'APPLIED', {})
      return
    default:
      respond(request, 'REJECTED', { reason: 'fixture broker does not implement ' + request.op })
  }
}

const startBroker = () => {
  const channel = new MessageChannel()
  brokerPort = channel.port1
  brokerPort.onmessage = event => handleRequest(event.data)
  const hello = {
    protocol: PROTOCOL,
    type: 'HELLO',
    seq: nextSeq(),
    grant_id: grantId,
    identity: IDENTITY,
    channel: PROTOCOL,
  }
  appFrame.contentWindow.postMessage(hello, opaque ? '*' : appOrigin, [channel.port2])
  if (!mode.holdGrant && !mode.wrongApp) sendGrant()
  else if (mode.wrongApp) sendGrant()
}

appFrame.addEventListener('load', () => { setTimeout(startBroker, 30) })
appFrame.src = appOrigin + '/'
if (attackOn) {
  attackFrame.src = '/attack/attack.html?app=' + encodeURIComponent(appOrigin)
}

window.__broker = {
  grantId,
  identity: IDENTITY,
  received,
  state: () => JSON.parse(JSON.stringify(state)),
  control: {
    holdNextOp: op => { mode.holdNextOp = op },
    releasePending: () => {
      for (const request of pending.splice(0)) {
        state.config_generation += 1
        state.config = JSON.parse(JSON.stringify(request.payload.candidate))
        respond(request, 'APPLIED', {
          session_generation: state.session_generation,
          config_generation: state.config_generation,
          snapshot: snapshotPayload(),
        })
      }
    },
    sendRevoke: reason => brokerPort.postMessage({
      protocol: PROTOCOL,
      type: 'REVOKE',
      seq: nextSeq(),
      grant_id: grantId,
      identity: IDENTITY,
      reason: reason || 'operator revoked the grant',
    }),
    setSeqRollbackNext: () => { mode.seqRollbackNext = true },
    setOversizeNext: () => { mode.oversizeNext = true },
    setStaleSessionEchoNext: () => { mode.staleSessionEchoNext = true },
    setRespondUnknownNext: () => { mode.respondUnknownNext = true },
    setRespondConflictNext: () => { mode.respondConflictNext = true },
    clearControl: () => {
      mode.holdNextOp = null
      mode.seqRollbackNext = false
      mode.oversizeNext = false
      mode.staleSessionEchoNext = false
      mode.respondUnknownNext = false
      mode.respondConflictNext = false
    },
  },
}
