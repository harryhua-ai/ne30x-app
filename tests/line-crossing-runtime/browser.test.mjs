import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { spawnSync } from 'node:child_process'
import { createReadStream, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import test, { after, before } from 'node:test'
import { fileURLToPath } from 'node:url'
import { chromium } from '../line-crossing-ui/browser-runner/node_modules/playwright-core/index.mjs'

const testRoot = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(testRoot, '../..')
const buildRoot = path.join(repoRoot, 'tests/line-crossing-ui/.build')
const productionRoot = path.join(buildRoot, 'production')
const h264Path = path.join(buildRoot, 'line-crossing-runtime.h264')
const fixtureRoot = path.join(testRoot, 'fixture')
const evidencePath = path.join(repoRoot, 'docs/evidence/line-crossing-runtime/runtime-fixture-evidence.json')
const signedProvenancePath = path.join(repoRoot, 'docs/evidence/line-crossing-ui/line-crossing.neui.provenance.json')
const signedProvenance = JSON.parse(readFileSync(signedProvenancePath, 'utf8'))
const chromePath = process.env.CHROME_PATH || (process.platform === 'darwin' ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : chromium.executablePath())
const HOST_HOSTNAME = 'host.example.test'
const APP_HOSTNAME = 'app.other.test'
const SIGNED_IDENTITY = {
  publisher_id: signedProvenance.manifest.publisher_id,
  app_id: signedProvenance.manifest.app_id,
  publisher_key_sha256: signedProvenance.signer_spki_sha256,
  native_tbs_sha256: signedProvenance.native_binding.native_tbs_sha256,
  ui_tbs_sha256: signedProvenance.ui_tbs_sha256,
  build_id: signedProvenance.source_commit,
  host_boot_generation: 3,
  native_session_generation: 11,
  ui_generation: 1,
  sidecar_service_generation: 2,
}

const CASES = [
  { id: 'authorized-session', title: 'authorized bridge session drives the real counting UI with real H264 workers and generation-checked writes', outcome: 'pass' },
  { id: 'fail-closed-variants', title: 'absent grants, wrong app identity, limited whitelists and opaque origins keep the App honest', outcome: 'pass' },
  { id: 'negative-traffic', title: 'rolled back, oversized, late and cross-generation results never pollute the bridge session', outcome: 'pass' },
  { id: 'enable-control-hidden', title: 'a granted business Enable capability stays non-interactive while normal config writes remain available', outcome: 'pass' },
  { id: 'sibling-forgery', title: 'a hostile sibling iframe cannot forge bridge traffic or reach App storage', outcome: 'pass' },
  { id: 'cross-site-isolation', title: 'the cross-site signed App cannot read Host DOM or storage or perform a cookie-authenticated admin write', outcome: 'pass' },
  { id: 'same-origin-relaxation', title: 'the same-origin control exposes Host DOM and storage to the signed App', outcome: 'negative-control' },
  { id: 'same-site-port-cookie-leak', title: 'the same-site port-only control sends the Host cookie with an App admin write', outcome: 'negative-control' },
]

const EVIDENCE = {
  app_entry: 'apps/line-crossing/ui/src/main.tsx (production build served from the current source tree)',
  signed_bundle: {
    bundle_path: signedProvenance.bundle_path,
    bundle_sha256: signedProvenance.bundle_sha256,
    ui_tbs_sha256: signedProvenance.ui_tbs_sha256,
    source_commit: signedProvenance.source_commit,
    signer_spki_sha256: signedProvenance.signer_spki_sha256,
    production_asset_equality: 'The historical signed NEUI bundle is checked against its own asset records; the current source build is exercised directly and packaged separately by NEPK v1.1.',
  },
  bridge_limits: { max_message_bytes: 16384, max_pending_requests: 4, request_deadline_ms: 10000 },
  browser: 'Chrome or Chromium with local resolver rules mapping host.example.test and app.other.test to 127.0.0.1',
  cases: CASES,
  origin_topology: {
    host: 'http://host.example.test:<ephemeral-port>',
    app: 'http://app.other.test:<ephemeral-port>',
    relation: 'independent sites mapped to loopback by Chrome --host-resolver-rules; no device DNS',
    same_site_port_control: 'http://host.example.test:<app-port> embeds under http://host.example.test:<host-port>',
  },
  isolation: {
    ac4_lab_status: 'PASS',
    app_sandbox: 'allow-scripts allow-same-origin',
    cross_site: 'Host HttpOnly SameSite=Strict cookie exists in the top-level Host context; the signed App receives SecurityError for parent DOM/storage, and a credentialed admin POST reaches the Host without the cookie and does not mutate admin state.',
    same_origin_control: 'Expected negative control: the same signed App served at the Host origin can read the parent marker and Host localStorage.',
    same_site_port_control: 'Expected negative control: the same Host hostname on a different TCP port remains same-site; the Strict cookie is sent and the fixture admin write succeeds.',
  },
  not_run: [
    'target deployment App/Host DNS, TLS, and site topology; the .test hostnames are local browser resolver aliases only',
    'target Host admin cookie/storage policy and admin API behavior beyond this isolated fixture endpoint',
    'opaque-origin App positive Worker/importScripts/H264 operation (opaque origin fail-closed is exercised instead)',
    'real device media grant, camera stream and target-board integration',
    'Host #88 policy engine, App #30 native Enable producer, Host #91/App #27 live producers (fixture answers UNAVAILABLE)',
  ],
  recording_download: 'NOT_RUN; signed FileSaver saveAs failure and the anchor fallback Host-token requirement remain open limitations.',
  protocol: 'ne301.sidecar.bridge.v1',
}

let browser
let appServer
let hostServer
let appUrl
let hostUrl
let streamEnabled = true
let frameUnits = []
let activeSockets = 0
let adminRequests = []
let adminWriteCount = 0
const streams = new Set()

const locateAccessUnits = bytes => {
  const starts = []
  for (let index = 0; index + 4 < bytes.length;) {
    if (bytes[index] === 0 && bytes[index + 1] === 0 && bytes[index + 2] === 0 && bytes[index + 3] === 1) {
      starts.push({ at: index, header: index + 4 })
      index += 4
    } else if (bytes[index] === 0 && bytes[index + 1] === 0 && bytes[index + 2] === 1) {
      starts.push({ at: index, header: index + 3 })
      index += 3
    } else index += 1
  }
  const aud = starts.filter(item => (bytes[item.header] & 31) === 9).map(item => item.at)
  const offsets = [0, ...aud.slice(1)]
  return offsets.map((offset, index) => bytes.subarray(offset, offsets[index + 1] ?? bytes.length))
}

const frameBuffer = (unit, sequence) => {
  const output = Buffer.alloc(64 + unit.length)
  output.writeUInt32BE(Math.floor(Date.now() / 1000) + Math.floor(sequence / 25), 12)
  unit.copy(output, 64)
  return output
}

const websocketFrame = payload => {
  if (payload.length < 126) return Buffer.concat([Buffer.from([0x82, payload.length]), payload])
  const header = Buffer.alloc(4)
  header[0] = 0x82
  header[1] = 126
  header.writeUInt16BE(payload.length, 2)
  return Buffer.concat([header, payload])
}

const mime = file => ({
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
}[path.extname(file)] || 'application/octet-stream')

const serveAsset = (request, response, root, prefixes) => {
  const url = new URL(request.url || '/', 'http://127.0.0.1')
  const prefix = prefixes.find(candidate => url.pathname.startsWith(candidate))
  if (!prefix) {
    response.statusCode = 404
    response.end('not found')
    return
  }
  let relative = url.pathname.slice(prefix.length) || '/'
  if (relative === '/') relative = prefix === '/' ? '/index.html' : `${prefix}.html`
  const normalized = path.normalize(decodeURIComponent(relative)).replace(/^([/\\]|\.\.(?:[/\\]|$))+/, '')
  const target = path.resolve(root, `.${path.sep}${normalized}`)
  if (!target.startsWith(`${path.resolve(root)}${path.sep}`) || !existsSync(target) || !statSync(target).isFile()) {
    response.statusCode = 404
    response.end('not found')
    return
  }
  response.setHeader('Content-Type', mime(target))
  createReadStream(target).pipe(response)
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

const waitFor = async (predicate, timeoutMs = 20000, message = 'condition not met') => {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await predicate()) return
    await sleep(200)
  }
  throw new Error(message)
}

const waitFrameState = async (frame, testId, expected, timeoutMs = 20000) => {
  await waitFor(
    async () => (await frame.getByTestId(testId).getAttribute('data-state').catch(() => null)) === expected,
    timeoutMs,
    `${testId} never reached data-state=${expected}`,
  )
}

const waitFrameText = async (frame, testId, expected, timeoutMs = 20000) => {
  await waitFor(
    async () => (await frame.getByTestId(testId).textContent().catch(() => '')) === expected,
    timeoutMs,
    `${testId} never showed "${expected}"`,
  )
}

const brokerReceived = page => page.evaluate(() => window.__broker.received)

const completedCaseIds = []
const completeCase = id => completedCaseIds.push(id)

before(async () => {
  assert.equal(existsSync(productionRoot), true, 'production build is missing; run the line-crossing-ui build first')
  assert.equal(existsSync(chromePath), true, 'Chrome or Chromium is required for the offline browser fixture')
  const generated = spawnSync('ffmpeg', [
    '-hide_banner', '-loglevel', 'error', '-f', 'lavfi', '-i', 'testsrc2=size=320x180:rate=25',
    '-t', '2', '-an', '-c:v', 'libx264', '-profile:v', 'baseline', '-preset', 'ultrafast', '-tune', 'zerolatency',
    '-g', '25', '-keyint_min', '25', '-sc_threshold', '0', '-x264-params', 'aud=1:repeat-headers=1',
    '-f', 'h264', '-y', h264Path,
  ], { encoding: 'utf8' })
  assert.equal(generated.status, 0, `${generated.stdout || ''}${generated.stderr || ''}`)
  frameUnits = locateAccessUnits(readFileSync(h264Path))
  assert.ok(frameUnits.length > 1)

  appServer = createServer((request, response) => {
    response.setHeader('Cache-Control', 'no-store')
    response.setHeader('Content-Security-Policy', `default-src 'self' blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' ws://${APP_HOSTNAME}:${appServer.address()?.port} ${hostUrl}; worker-src 'self' blob:; object-src 'none'; base-uri 'none'`)
    serveAsset(request, response, productionRoot, ['/'])
  })
  appServer.on('upgrade', (request, socket) => {
    const key = request.headers['sec-websocket-key']
    if (!streamEnabled || request.url?.split('?')[0] !== '/stream' || typeof key !== 'string') {
      socket.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n')
      socket.destroy()
      return
    }
    const accept = createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64')
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`)
    socket.setNoDelay(true)
    activeSockets += 1
    streams.add(socket)
    let sequence = 0
    const timer = setInterval(() => {
      if (socket.destroyed || socket.writableEnded || !socket.writable) return
      try {
        socket.write(websocketFrame(frameBuffer(frameUnits[sequence % frameUnits.length], sequence)))
      } catch {
        clearInterval(timer)
      }
      sequence += 1
    }, 40)
    socket.on('error', () => undefined)
    socket.on('close', () => {
      clearInterval(timer)
      streams.delete(socket)
      activeSockets -= 1
    })
  })
  hostServer = createServer((request, response) => {
    response.setHeader('Cache-Control', 'no-store')
    const requestUrl = new URL(request.url || '/', `http://${HOST_HOSTNAME}`)
    if (requestUrl.pathname === '/admin/write') {
      const cookie = request.headers.cookie || ''
      const authenticated = /(?:^|;\s*)host_admin=fixture-secret(?:;|$)/.test(cookie)
      const statusCode = authenticated ? 200 : 401
      adminRequests.push({
        origin: request.headers.origin || null,
        cookie_present: authenticated,
        host: request.headers.host,
        method: request.method,
        status: statusCode,
      })
      if (request.headers.origin === `http://${request.headers.host}`) {
        response.setHeader('Access-Control-Allow-Origin', request.headers.origin)
        response.setHeader('Access-Control-Allow-Credentials', 'true')
      }
      response.setHeader('Content-Type', 'application/json')
      response.statusCode = statusCode
      if (authenticated) adminWriteCount += 1
      response.end(JSON.stringify({ written: authenticated }))
      return
    }
    if (requestUrl.pathname === '/signed-app' || requestUrl.pathname.startsWith('/signed-app/')) {
      const origin = `http://${request.headers.host}`
      response.setHeader('Content-Security-Policy', `default-src 'self' blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' ${origin.replace(/^http/, 'ws')}; worker-src 'self' blob:; object-src 'none'; base-uri 'none'`)
      request.url = requestUrl.pathname.slice('/signed-app'.length) || '/'
      serveAsset(request, response, productionRoot, ['/'])
      return
    }
    response.setHeader('Content-Security-Policy', `default-src 'none'; script-src 'self'; style-src 'self'; frame-src http://${APP_HOSTNAME}:* http://${HOST_HOSTNAME}:*; connect-src 'none'; base-uri 'none'`)
    if (requestUrl.pathname === '/host' || requestUrl.pathname.startsWith('/host/')) {
      response.setHeader('Set-Cookie', 'host_admin=fixture-secret; Path=/; SameSite=Strict; HttpOnly')
    }
    serveAsset(request, response, fixtureRoot, ['/host', '/attack'])
  })
  await Promise.all([
    new Promise((resolve, reject) => { appServer.once('error', reject); appServer.listen(0, '127.0.0.1', resolve) }),
    new Promise((resolve, reject) => { hostServer.once('error', reject); hostServer.listen(0, '127.0.0.1', resolve) }),
  ])
  appUrl = `http://${APP_HOSTNAME}:${appServer.address().port}`
  hostUrl = `http://${HOST_HOSTNAME}:${hostServer.address().port}`
  browser = await chromium.launch({
    executablePath: chromePath,
    headless: true,
    args: [
      '--no-sandbox',
      '--autoplay-policy=no-user-gesture-required',
      `--host-resolver-rules=MAP ${HOST_HOSTNAME} 127.0.0.1,MAP ${APP_HOSTNAME} 127.0.0.1`,
    ],
  })
})

after(async () => {
  for (const socket of streams) socket.destroy()
  await browser?.close()
  await new Promise(resolve => appServer?.close(() => resolve()))
  await new Promise(resolve => hostServer?.close(() => resolve()))
})

const openHostPage = async (query, browserContext = null, origins = {}) => {
  const page = await (browserContext ? browserContext.newPage() : browser.newPage({ viewport: { width: 1280, height: 900 }, locale: 'en-US' }))
  const workers = []
  page.on('worker', worker => workers.push(worker.url()))
  const targetHostUrl = origins.hostUrl || hostUrl
  const targetAppUrl = origins.appUrl || appUrl
  const params = new URLSearchParams(query)
  params.set('app', targetAppUrl)
  params.set('identity', JSON.stringify(SIGNED_IDENTITY))
  await page.goto(`${targetHostUrl}/host/?${params}`, { waitUntil: 'load' })
  const frame = page.frameLocator('#appFrame')
  return { page, frame, workers, targetAppUrl }
}

const authorize = async query => {
  const { page, frame, workers, targetAppUrl } = await openHostPage(query)
  await waitFrameState(frame, 'lc-app-state', 'available')
  return { page, frame, workers, targetAppUrl }
}

const locateAppBrowserFrame = (page, targetAppUrl) => {
  const origin = new URL(targetAppUrl).origin
  return page.frames().find(candidate => candidate.parentFrame() === page.mainFrame() && candidate.url().startsWith(origin))
}

const probeHostBoundary = (appFrame, adminUrl) => appFrame.evaluate(async target => {
  let parentDom
  let parentStorage
  try {
    parentDom = `accessible: ${window.parent.document.querySelector('#host-admin-marker')?.textContent.trim() || 'marker missing'}`
  } catch (error) {
    parentDom = `blocked: ${error.name}`
  }
  try {
    parentStorage = `accessible: ${window.parent.localStorage.getItem('host-admin-fixture')}`
  } catch (error) {
    parentStorage = `blocked: ${error.name}`
  }
  let adminWrite
  try {
    const response = await fetch(`${target}/admin/write`, {
      method: 'POST',
      mode: 'cors',
      credentials: 'include',
      headers: { 'Content-Type': 'text/plain' },
      body: 'fixture-write',
    })
    adminWrite = { result: 'resolved', status: response.status, body: await response.json() }
  } catch (error) {
    adminWrite = { result: 'rejected', name: error.name }
  }
  return { parentDom, parentStorage, adminWrite }
}, adminUrl)

const prepareDraft = async (frame, name) => {
  await frame.getByTestId('lc-tab-config').click()
  await frame.getByTestId('lc-page-config').waitFor()
  await frame.getByTestId('lc-counter-name').fill(name)
}

const saveCounterName = async (frame, name) => {
  await prepareDraft(frame, name)
  await frame.getByTestId('lc-save-config').click()
}

test(CASES[0].title, async () => {
  const { page, frame, workers, targetAppUrl } = await authorize('scenario=normal&enable=unavailable&live=unavailable')
  assert.deepEqual(await page.evaluate(() => window.__broker.identity), SIGNED_IDENTITY)
  await frame.getByTestId('lc-tab-config').click()
  await frame.getByTestId('lc-page-config').waitFor()
  assert.equal(await frame.getByTestId('lc-counter-name').inputValue(), 'Counter Bridge')
  assert.equal(await frame.getByTestId('lc-business-enable-switch').count(), 0)
  assert.equal(await frame.getByTestId('lc-business-enable').count(), 0)

  await frame.getByTestId('lc-tab-realtime').click()
  assert.ok(await frame.getByTestId('lc-stat-cell').count() >= 4)
  assert.match(await frame.getByTestId('lc-stat-cell').first().textContent(), /5/)
  assert.equal(await frame.getByTestId('lc-events-unavailable').count(), 1)
  assert.equal(await frame.getByTestId('lc-track').count(), 0)

  await waitFor(async () => (await brokerReceived(page)).some(item => item.op === 'video.open'), 20000, 'the authorized App never auto-requested the video grant')
  assert.equal((await brokerReceived(page)).filter(item => item.op === 'video.open').length, 1)
  await waitFrameState(frame, 'lc-video-state', 'live', 30000)
  await waitFor(async () => workers.length >= 2, 10000, 'the signed App did not start both video workers')
  const workerUrls = workers.map(workerUrl => new URL(workerUrl))
  assert.equal(workerUrls.some(workerUrl => workerUrl.pathname.includes('websocket-init')), true)
  assert.equal(workerUrls.some(workerUrl => workerUrl.pathname.includes('videoWorker')), true)
  assert.equal(workerUrls.every(workerUrl => workerUrl.origin === new URL(targetAppUrl).origin), true)
  const playback = await frame.locator('#lcVideoPlayer').evaluate(video => ({ width: video.videoWidth, height: video.videoHeight, time: video.currentTime }))
  assert.deepEqual([playback.width, playback.height], [320, 180])
  assert.ok(playback.time > 0)
  const videoOpen = (await brokerReceived(page)).find(item => item.op === 'video.open')
  assert.equal(videoOpen.payload.session_generation, 8)
  await sleep(6500)
  assert.equal((await brokerReceived(page)).filter(item => item.op === 'video.close').length, 0)
  assert.equal((await brokerReceived(page)).filter(item => item.op === 'video.open').length, 1)

  await saveCounterName(frame, 'Counter Renamed')
  await waitFor(async () => (await brokerReceived(page)).some(item => item.op === 'config.apply'), 20000, 'config.apply never reached the broker')
  const apply = (await brokerReceived(page)).find(item => item.op === 'config.apply')
  assert.equal(apply.payload.session_generation, 8)
  assert.equal(apply.payload.expected_config_generation, 12)
  assert.equal(apply.payload.candidate.counter_name, 'Counter Renamed')
  assert.equal(Object.hasOwn(apply.payload.candidate, 'backlog_capacity'), false)
  await waitFrameText(frame, 'lc-save-status', 'Applied')
  await waitFor(async () => (await frame.getByTestId('lc-counter-name').inputValue()) === 'Counter Renamed', 20000, 'the APPLIED counter name never round-tripped into the draft')
  assert.equal((await page.evaluate(() => window.__broker.state())).config_generation, 13)

  await frame.getByTestId('lc-tab-advanced').click()
  await frame.getByTestId('lc-page-advanced').waitFor()
  await frame.getByTestId('lc-host-backlog-capacity').locator('input').fill('64')
  await frame.getByTestId('lc-save-host').click()
  await waitFor(async () => (await brokerReceived(page)).some(item => item.op === 'report-policy.apply'), 20000, 'report-policy.apply never reached the broker')
  const policyApply = (await brokerReceived(page)).find(item => item.op === 'report-policy.apply')
  assert.equal(policyApply.payload.expected_generation, 4)
  assert.equal(policyApply.payload.candidate.backlog_capacity, 64)
  await waitFrameText(frame, 'lc-host-save-status', 'Applied')

  await frame.getByTestId('lc-tab-realtime').click()
  await frame.getByTestId('lc-reset-stats').click()
  await frame.getByTestId('lc-reset-dialog').waitFor()
  await frame.locator('[data-testid="lc-reset-dialog"] button').last().click()
  await waitFor(async () => (await brokerReceived(page)).some(item => item.op === 'counters.reset'), 20000, 'counters.reset never reached the broker')
  await waitFor(async () => (await frame.getByTestId('lc-stat-cell').first().textContent()).includes('0'), 20000, 'stats were not refreshed to the reset values')

  const receivedBeforeRevoke = (await brokerReceived(page)).length
  await page.evaluate(() => window.__broker.control.sendRevoke('operator revoked the grant'))
  await waitFrameState(frame, 'lc-app-state', 'unavailable')
  await waitFrameState(frame, 'lc-video-state', 'unavailable')
  await waitFor(async () => activeSockets === 0, 10000, 'the media websocket stayed open after revocation')
  await sleep(1200)
  assert.equal((await brokerReceived(page)).length, receivedBeforeRevoke, 'the revoked App kept sending bridge requests')
  completeCase(CASES[0].id)
  await page.close()
})

test(CASES[1].title, async () => {
  for (const [label, query] of [
    ['no grant', 'scenario=noGrant'],
    ['wrong app identity', 'scenario=wrongApp'],
    ['opaque app origin', 'scenario=opaque'],
  ]) {
    const { page, frame } = await openHostPage(query)
    await sleep(2500)
    const appState = await frame.getByTestId('lc-app-state').getAttribute('data-state').catch(() => null)
    if (query === 'scenario=opaque') {
      assert.equal(appState === null || appState === 'unavailable', true, `${label}: the opaque-origin App must not authorize (its asset CSP blocks scripts entirely in this fixture)`)
    } else {
      assert.equal(appState, 'unavailable', label)
      assert.equal(await frame.getByTestId('lc-video-state').getAttribute('data-state'), 'unavailable', label)
      await frame.getByTestId('lc-tab-config').click()
      await frame.getByTestId('lc-config-unavailable').waitFor()
      assert.equal(await frame.getByTestId('lc-config-unavailable').count(), 1, label)
      assert.equal(await frame.getByTestId('lc-save-config').isDisabled(), true, label)
    }
    assert.equal(await brokerReceived(page).then(items => items.length), 0, label)
    await page.close()
  }

  const { page, frame } = await authorize('scenario=limited&enable=unavailable')
  await frame.getByTestId('lc-tab-config').click()
  await frame.getByTestId('lc-page-config').waitFor()
  assert.equal(await frame.getByTestId('lc-save-config').isDisabled(), true)
  await frame.getByTestId('lc-tab-realtime').click()
  await frame.getByTestId('lc-page-realtime').waitFor()
  assert.equal(await frame.getByTestId('lc-reset-stats').isDisabled(), true)
  await frame.getByTestId('lc-tab-advanced').click()
  await frame.getByTestId('lc-page-advanced').waitFor()
  await frame.getByTestId('lc-host-backlog-capacity').locator('input').fill('40')
  await frame.getByTestId('lc-save-host').click()
  await waitFrameText(frame, 'lc-host-save-status', 'Applied')
  const ops = (await brokerReceived(page)).map(item => item.op)
  assert.equal(ops.includes('config.apply'), false)
  assert.equal(ops.includes('counters.reset'), false)
  assert.equal(ops.includes('report-policy.apply'), true)
  completeCase(CASES[1].id)
  await page.close()
})

test(CASES[2].title, async () => {
  const rolled = await authorize('scenario=normal&enable=unavailable')
  await prepareDraft(rolled.frame, 'Rollback Check')
  await rolled.page.evaluate(() => window.__broker.control.setSeqRollbackNext())
  await rolled.frame.getByTestId('lc-save-config').click()
  await waitFrameText(rolled.frame, 'lc-save-status', 'Applied')
  assert.equal(await rolled.frame.getByTestId('lc-app-state').getAttribute('data-state'), 'available')
  assert.equal((await rolled.page.evaluate(() => window.__broker.state())).config_generation, 13)
  await rolled.page.close()

  const oversized = await authorize('scenario=normal&enable=unavailable')
  await prepareDraft(oversized.frame, 'Oversize Check')
  await oversized.page.evaluate(() => window.__broker.control.setOversizeNext())
  await oversized.frame.getByTestId('lc-save-config').click()
  await waitFrameText(oversized.frame, 'lc-save-status', 'App session changed; reload the current snapshot')
  await waitFrameState(oversized.frame, 'lc-app-state', 'unavailable')
  const receivedAfterOversize = await brokerReceived(oversized.page)
  await sleep(1200)
  assert.deepEqual(await brokerReceived(oversized.page), receivedAfterOversize)
  await oversized.page.close()

  const late = await authorize('scenario=normal&enable=unavailable')
  await prepareDraft(late.frame, 'Late ACK Check')
  await late.page.evaluate(() => window.__broker.control.holdNextOp('config.apply'))
  await late.frame.getByTestId('lc-save-config').click()
  await waitFor(async () => (await brokerReceived(late.page)).some(item => item.op === 'config.apply'), 20000, 'held config.apply never reached the broker')
  await late.page.evaluate(() => window.__broker.control.sendRevoke('operator revoked the grant'))
  await waitFrameText(late.frame, 'lc-save-status', 'App session changed; reload the current snapshot')
  await late.page.evaluate(() => window.__broker.control.releasePending())
  await sleep(1200)
  assert.equal(await late.frame.getByTestId('lc-save-status').textContent(), 'App session changed; reload the current snapshot', 'the late APPLIED was committed after revocation')
  assert.equal(await late.frame.getByTestId('lc-app-state').getAttribute('data-state'), 'unavailable')
  assert.equal((await brokerReceived(late.page)).filter(item => item.op === 'config.apply').length, 1, 'the revoked App re-sent or duplicated the config write')
  await late.page.close()

  const stale = await authorize('scenario=normal&enable=unavailable')
  await prepareDraft(stale.frame, 'Stale Echo Check')
  await stale.page.evaluate(() => window.__broker.control.setStaleSessionEchoNext())
  await stale.frame.getByTestId('lc-save-config').click()
  await waitFrameText(stale.frame, 'lc-save-status', 'Outcome unknown; no automatic retry was sent')
  assert.equal(await stale.frame.getByTestId('lc-app-state').getAttribute('data-state'), 'available')
  assert.equal((await stale.page.evaluate(() => window.__broker.state())).config_generation, 12, 'the stale-echo APPLIED mutated the broker generation bookkeeping')
  await stale.frame.getByTestId('lc-counter-name').fill('Clean Rename')
  await stale.frame.getByTestId('lc-save-config').click()
  await waitFrameText(stale.frame, 'lc-save-status', 'Applied')
  assert.equal((await stale.page.evaluate(() => window.__broker.state())).config_generation, 13)
  completeCase(CASES[2].id)
  await stale.page.close()
})

test(CASES[3].title, async () => {
  const { page, frame } = await authorize('scenario=normal&enable=available')
  await frame.getByTestId('lc-tab-config').click()
  await frame.getByTestId('lc-page-config').waitFor()
  await waitFor(async () => (await brokerReceived(page)).some(item => item.op === 'enable.read'), 20000, 'the available Enable capability was not read by the runtime')
  assert.equal((await page.evaluate(() => window.__broker.state())).enable, false)
  assert.equal(await frame.getByTestId('lc-business-enable').count(), 0)
  assert.equal(await frame.getByTestId('lc-business-enable-switch').count(), 0)
  assert.equal(await frame.getByRole('switch').count(), 0)
  assert.equal(await frame.getByRole('checkbox').count(), 0)
  assert.equal(await frame.getByText(/pause|disable counting|stop counting/i).count(), 0)
  assert.equal((await brokerReceived(page)).some(item => item.op === 'enable.apply'), false)

  await saveCounterName(frame, 'Counter Still Configurable')
  await waitFor(async () => (await brokerReceived(page)).some(item => item.op === 'config.apply'), 20000, 'normal config.apply never reached the broker')
  assert.equal((await brokerReceived(page)).some(item => item.op === 'enable.apply'), false)
  await waitFrameText(frame, 'lc-save-status', 'Applied')
  completeCase(CASES[3].id)
  await page.close()
})

test(CASES[4].title, async () => {
  const { page, frame } = await authorize('scenario=normal&enable=unavailable')
  const attackFrame = page.frames().find(candidate => candidate.url().includes('/attack/attack.html'))
  assert.ok(attackFrame, 'the hostile sibling iframe did not load')
  await sleep(1800)
  const attempts = await attackFrame.evaluate(() => window.__attack)
  assert.equal(attempts.forgedMessages >= 10, true, 'the sibling fixture did not run its forgery loop')
  assert.match(attempts.storageAccess, /^blocked: SecurityError/)
  assert.match(attempts.domAccess, /^blocked: SecurityError/)

  await saveCounterName(frame, 'After Forgery')
  await waitFrameText(frame, 'lc-save-status', 'Applied')
  assert.equal(await frame.getByTestId('lc-app-state').getAttribute('data-state'), 'available')
  assert.equal(await frame.getByTestId('lc-counter-name').inputValue(), 'After Forgery')
  completeCase(CASES[4].id)
  await page.close()
})

test('cross-site App cannot read Host DOM or storage or perform a cookie-authenticated admin write', async () => {
  const { page, frame, targetAppUrl } = await openHostPage('scenario=normal&attack=off')
  await waitFrameState(frame, 'lc-app-state', 'available')
  assert.equal(new URL(hostUrl).hostname, HOST_HOSTNAME)
  assert.equal(new URL(targetAppUrl).hostname, APP_HOSTNAME)
  const hostCookie = (await page.context().cookies(hostUrl)).find(cookie => cookie.name === 'host_admin')
  assert.ok(hostCookie, 'the Host top-level context did not retain its admin cookie')
  assert.equal(hostCookie.httpOnly, true)
  assert.equal(hostCookie.sameSite, 'Strict')

  adminRequests = []
  adminWriteCount = 0
  const appFrame = locateAppBrowserFrame(page, targetAppUrl)
  assert.ok(appFrame, 'the signed App frame did not load on app.other.test')
  const probe = await probeHostBoundary(appFrame, hostUrl)
  assert.match(probe.parentDom, /^blocked: SecurityError/)
  assert.match(probe.parentStorage, /^blocked: SecurityError/)
  assert.deepEqual(probe.adminWrite, { result: 'rejected', name: 'TypeError' })
  await waitFor(async () => adminRequests.length === 1, 10000, 'the cross-site credentialed admin request never reached the Host fixture')
  assert.equal(adminRequests[0].origin, targetAppUrl)
  assert.equal(adminRequests[0].cookie_present, false)
  assert.equal(adminRequests[0].status, 401)
  assert.equal(adminWriteCount, 0)
  completeCase('cross-site-isolation')
  await page.close()
})

test('same-origin control allows the signed App to read Host DOM and storage', async () => {
  const sameOriginAppUrl = `${hostUrl}/signed-app`
  const { page, frame, targetAppUrl } = await openHostPage('scenario=normal&attack=off', null, { appUrl: sameOriginAppUrl })
  await waitFrameState(frame, 'lc-app-state', 'available')
  adminRequests = []
  adminWriteCount = 0
  const appFrame = locateAppBrowserFrame(page, targetAppUrl)
  assert.ok(appFrame, 'the same-origin signed App frame did not load')
  const probe = await probeHostBoundary(appFrame, hostUrl)
  assert.match(probe.parentDom, /^accessible: Host administration fixture/)
  assert.equal(probe.parentStorage, 'accessible: fixture-secret')
  assert.deepEqual(probe.adminWrite, { result: 'resolved', status: 200, body: { written: true } })
  assert.equal(adminRequests.length, 1)
  assert.equal(adminRequests[0].cookie_present, true)
  assert.equal(adminRequests[0].status, 200)
  assert.equal(adminWriteCount, 1)
  completeCase('same-origin-relaxation')
  await page.close()
})

test('same-site port-only control leaks the Host cookie to a cross-origin App', async () => {
  const portOnlyAppUrl = `http://${HOST_HOSTNAME}:${appServer.address().port}`
  const { page, frame, targetAppUrl } = await openHostPage('scenario=normal&attack=off', null, { appUrl: portOnlyAppUrl })
  await waitFrameState(frame, 'lc-app-state', 'available')
  assert.notEqual(new URL(targetAppUrl).origin, new URL(hostUrl).origin)
  assert.equal(new URL(targetAppUrl).hostname, new URL(hostUrl).hostname)
  adminRequests = []
  adminWriteCount = 0
  const appFrame = locateAppBrowserFrame(page, targetAppUrl)
  assert.ok(appFrame, 'the port-only App frame did not load')
  const probe = await probeHostBoundary(appFrame, hostUrl)
  assert.match(probe.parentDom, /^blocked: SecurityError/)
  assert.match(probe.parentStorage, /^blocked: SecurityError/)
  assert.deepEqual(probe.adminWrite, { result: 'rejected', name: 'TypeError' })
  await waitFor(async () => adminRequests.length === 1, 10000, 'the port-only admin request never reached the Host fixture')
  assert.equal(adminRequests[0].cookie_present, true)
  assert.equal(adminRequests[0].status, 200)
  assert.equal(adminWriteCount, 1)
  completeCase('same-site-port-cookie-leak')
  await page.close()
})

test('committed runtime fixture evidence matches the executed browser cases', async () => {
  assert.deepEqual(completedCaseIds.sort(), CASES.map(item => item.id).sort(), 'not every fixture case completed; evidence would be misleading')
  if (process.env.WRITE_EVIDENCE) {
    mkdirSync(path.dirname(evidencePath), { recursive: true })
    writeFileSync(evidencePath, `${JSON.stringify(EVIDENCE, null, 2)}\n`)
    return
  }
  const committed = JSON.parse(readFileSync(evidencePath, 'utf8'))
  assert.deepEqual(committed.cases, CASES)
  assert.deepEqual(committed.signed_bundle, EVIDENCE.signed_bundle)
  assert.equal(committed.protocol, EVIDENCE.protocol)
  assert.deepEqual(committed.bridge_limits, EVIDENCE.bridge_limits)
  assert.deepEqual(committed.origin_topology, EVIDENCE.origin_topology)
  assert.deepEqual(committed.isolation, EVIDENCE.isolation)
  assert.deepEqual(committed.not_run, EVIDENCE.not_run)
  assert.equal(committed.recording_download, EVIDENCE.recording_download)
})
