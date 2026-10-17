const params = new URLSearchParams(window.location.search)
const appOrigin = params.get('app')
const appFrame = window.parent.document.querySelector('#appFrame')
const appWindow = appFrame.contentWindow

const attempts = { storageAccess: null, domAccess: null, forgedMessages: 0 }

const forgedIdentity = {
  publisher_id: 'attacker',
  app_id: 'line-crossing',
  publisher_key_sha256: 'f'.repeat(64),
  native_tbs_sha256: 'f'.repeat(64),
  ui_tbs_sha256: 'f'.repeat(64),
  build_id: 'forged-build',
  host_boot_generation: 0,
  native_session_generation: 0,
  ui_generation: 0,
  sidecar_service_generation: 0,
}
const forgedGrantId = 'forgedgrantforgedgrant00'

const forge = (type, extra) => ({
  protocol: 'ne301.sidecar.bridge.v1',
  type,
  seq: 4294000000,
  grant_id: forgedGrantId,
  identity: forgedIdentity,
  ...extra,
})

const forgedSnapshot = {
  session_generation: 8,
  config_generation: 999,
  config: { schema: 1, counter_name: 'FORGED', target_class_name: 'person' },
  status: { state: 'running', target_class: 'person' },
  stats: { window: { in: 0, out: 0 }, total: { in: 0, out: 0 } },
}

const forgedResult = op => forge('RESULT', {
  request_id: 1,
  op,
  outcome: 'APPLIED',
  payload: op === 'snapshot.read' ? forgedSnapshot : { ...forgedSnapshot },
})

const attackOnce = () => {
  const channel = new MessageChannel()
  appWindow.postMessage(forge('HELLO', { channel: 'ne301.sidecar.bridge.v1' }), appOrigin, [channel.port2])
  appWindow.postMessage(forgedResult('snapshot.read'), appOrigin)
  appWindow.postMessage(forgedResult('config.apply'), appOrigin)
  appWindow.postMessage(forge('EVENT', { payload: { stream: 'live', stream_seq: 1, data: { server_now_ms: 1 } } }), appOrigin)
  appWindow.postMessage(forge('REVOKE', { reason: 'forged revoke' }), appOrigin)
  attempts.forgedMessages += 5
}

const attackAfterAppNavigation = () => {
  try {
    if (new URL(appWindow.location.href).origin !== new URL(appOrigin).origin) {
      setTimeout(attackAfterAppNavigation, 25)
      return
    }
  } catch {}

  try {
    attempts.storageAccess = 'read length ' + appWindow.localStorage.length
  } catch (error) {
    attempts.storageAccess = 'blocked: ' + error.name
  }
  try {
    attempts.domAccess = 'read body ' + appWindow.document.body.tagName
  } catch (error) {
    attempts.domAccess = 'blocked: ' + error.name
  }
  attackOnce()
  setInterval(attackOnce, 700)
}

attackAfterAppNavigation()
window.__attack = attempts
