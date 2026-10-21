import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { spawnSync } from 'node:child_process'
import { createReadStream, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import test, { after, before } from 'node:test'
import { chromium } from './browser-runner/node_modules/playwright-core/index.mjs'
import { fileURLToPath } from 'node:url'

const testRoot = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(testRoot, '../..')
const buildRoot = path.join(testRoot, '.build')
const productionRoot = path.join(buildRoot, 'production')
const browserRoot = path.join(buildRoot, 'browser')
const signedRoot = path.join(buildRoot, 'signed')
const h264Path = path.join(buildRoot, 'line-crossing-test.h264')
const lineCountingSource = readFileSync(path.join(repoRoot, 'apps/line-crossing/ui/src/LineCountingModule.tsx'), 'utf8')
const freshnessMatch = lineCountingSource.match(/const FRESH_FOR_MS\s*=\s*(\d+)\s*;/)
if (!freshnessMatch) throw new Error('could not read the production capability freshness interval')
const capabilityFreshForMs = Number(freshnessMatch[1])
const chromePath = process.env.CHROME_PATH || (process.platform === 'darwin' ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : chromium.executablePath())
let browser
let server
let serverUrl
let streamEnabled = true
let frameUnits = []
const streams = new Map()
const requests = []

const captureSaveBoundary = page => page.evaluate((freshForMs) => {
  const testApi = window.__lineCrossingTest
  const state = testApi.getState()
  const now = Date.now()
  const describe = capability => {
    if (!capability || capability.state !== 'available') return { state: capability?.state ?? 'missing' }
    const observedAtMs = capability.observedAtMs ?? capability.value?.observedAtMs ?? null
    const ageMs = observedAtMs === null ? null : now - observedAtMs
    return {
      state: capability.state,
      observedAtMs,
      ageMs,
      expiresAtMs: observedAtMs === null ? null : observedAtMs + freshForMs,
      remainingMs: ageMs === null ? null : freshForMs - ageMs,
    }
  }
  const finishButton = document.querySelector('[data-testid="lc-line-toolbar"] button')
  const discardButton = document.querySelector('[data-testid="lc-discard"]')
  const appSnapshot = state.app?.state === 'available' ? state.app.value : null
  const lineSaveButton = document.querySelector('[data-testid="lc-line-toolbar"] button')
  const appAgeMs = appSnapshot ? now - appSnapshot.observedAtMs : null
  const appCapabilityAgeMs = state.app?.state === 'available' ? now - state.app.observedAtMs : null
  const configWriteAgeMs = state.configWrite?.state === 'available' ? now - state.configWrite.observedAtMs : null
  const computedWriteAllowed = appSnapshot !== null
    && appAgeMs <= freshForMs
    && appCapabilityAgeMs <= freshForMs
    && state.configWrite?.state === 'available'
    && configWriteAgeMs <= freshForMs
    && state.configWrite.value === true
  return {
    capturedAtMs: now,
    editMode: Boolean(document.querySelector('[data-testid="lc-toolbar-hint"]')),
    dirty: discardButton ? !discardButton.disabled : false,
    writeAllowed: computedWriteAllowed,
    appCapabilityAgeMs,
    appSnapshotAgeMs: appAgeMs,
    configWriteAgeMs,
    toolbarDisabled: finishButton?.disabled ?? null,
    lineSaveButtonDisabled: lineSaveButton?.disabled ?? null,
    appWriteCallCount: testApi.getCalls().app.length,
    saveClickEvents: window.__lineCrossingSaveClicks ?? [],
    saveStatus: document.querySelector('[data-testid="lc-app-save-status"]')?.textContent ?? null,
    appState: document.querySelector('[data-testid="lc-app-state"]')?.getAttribute('data-state') ?? null,
    appCapability: describe(state.app),
    appSnapshot: describe(appSnapshot ? { state: 'available', value: appSnapshot } : null),
    configWriteCapability: describe(state.configWrite),
    pointerEvents: window.__lineCrossingPointerEvents ?? [],
    videoState: document.querySelector('[data-testid="lc-video-state"]')?.getAttribute('data-state') ?? null,
  }
}, capabilityFreshForMs)

const recordSaveBoundary = evidence => {
  const evidencePath = process.env.LC_SAVE_EVIDENCE_PATH
  if (!evidencePath) return
  const records = existsSync(evidencePath) ? JSON.parse(readFileSync(evidencePath, 'utf8')) : []
  records.push(evidence)
  mkdirSync(path.dirname(evidencePath), { recursive: true })
  writeFileSync(evidencePath, `${JSON.stringify(records, null, 2)}\n`)
}

const observeSavePointerEvents = page => page.evaluate(() => {
  window.__lineCrossingPointerEvents = []
  window.__lineCrossingSaveClicks = []
  for (const type of ['pointerdown', 'pointermove', 'pointerup', 'pointercancel']) {
    window.addEventListener(type, event => {
      const target = event.target instanceof Element ? event.target.closest('[data-testid]') : null
      window.__lineCrossingPointerEvents.push({
        type,
        pointerType: event.pointerType,
        button: event.button,
        isPrimary: event.isPrimary,
        clientX: Math.round(event.clientX),
        clientY: Math.round(event.clientY),
        targetTestId: target?.getAttribute('data-testid') ?? null,
      })
    }, true)
  }
  document.addEventListener('click', event => {
    const button = event.target instanceof Element ? event.target.closest('[data-testid="lc-line-toolbar"] button') : null
    if (button) window.__lineCrossingSaveClicks.push({ isTrusted: event.isTrusted, detail: event.detail })
  }, true)
})

const waitForFirstLineApply = async (page, scenario, injection, expectTimeout = false) => {
  const startedAtMs = Date.now()
  await page.evaluate(() => {
    window.__lineCrossingSaveWait = { startedAt: performance.now(), nextStage: 0, stages: [] }
  })
  try {
    await page.waitForFunction(() => {
      const tracker = window.__lineCrossingSaveWait
      const elapsedMs = performance.now() - tracker.startedAt
      const thresholds = [1000, 5000, 10000]
      while (tracker.nextStage < thresholds.length && elapsedMs >= thresholds[tracker.nextStage]) {
        const state = window.__lineCrossingTest.getState()
        const now = Date.now()
        const app = state.app?.state === 'available' ? state.app.value : null
        const write = state.configWrite
        const appAgeMs = app ? now - app.observedAtMs : null
        const appCapabilityAgeMs = state.app?.state === 'available' ? now - state.app.observedAtMs : null
        const writeAgeMs = write?.state === 'available' ? now - write.observedAtMs : null
        const button = document.querySelector('[data-testid="lc-line-toolbar"] button')
        const discard = document.querySelector('[data-testid="lc-discard"]')
        tracker.stages.push({
          elapsedMs: Math.round(elapsedMs),
          capturedAtMs: now,
          appWriteCallCount: window.__lineCrossingTest.getCalls().app.length,
          editMode: Boolean(document.querySelector('[data-testid="lc-toolbar-hint"]')),
          dirty: discard ? !discard.disabled : false,
          writeAllowed: app !== null && appAgeMs <= 10000 && appCapabilityAgeMs <= 10000 && write?.state === 'available' && writeAgeMs <= 10000 && write.value === true,
          toolbarDisabled: button?.disabled ?? null,
          appAgeMs,
          appCapabilityAgeMs,
          appRemainingMs: appAgeMs === null ? null : 10000 - appAgeMs,
          configWriteAgeMs: writeAgeMs,
          configWriteRemainingMs: writeAgeMs === null ? null : 10000 - writeAgeMs,
          saveClickEvents: window.__lineCrossingSaveClicks ?? [],
          pointerEvents: window.__lineCrossingPointerEvents ?? [],
        })
        tracker.nextStage += 1
      }
      return window.__lineCrossingTest.getCalls().app.length === 1
    }, null, { timeout: 30000, polling: 100 })
  } catch (error) {
    const elapsedMs = Date.now() - startedAtMs
    const waitStages = await page.evaluate(() => window.__lineCrossingSaveWait.stages)
    const timeoutState = { phase: 'apply-timeout', scenario, injection, elapsedMs, waitStages, ...await captureSaveBoundary(page) }
    recordSaveBoundary(timeoutState)
    console.log(`LC_SAVE_TIMEOUT ${JSON.stringify(timeoutState)}`)
    if (expectTimeout && /Timeout 30000ms exceeded/.test(String(error))) return { timedOut: true, elapsedMs, error, evidence: timeoutState }
    throw error
  }
  const elapsedMs = Date.now() - startedAtMs
  const waitStages = await page.evaluate(() => window.__lineCrossingSaveWait.stages)
  const applied = { phase: 'apply-observed', scenario, injection, elapsedMs, waitStages, ...await captureSaveBoundary(page) }
  recordSaveBoundary(applied)
  console.log(`LC_SAVE_APPLY ${JSON.stringify(applied)}`)
  return { timedOut: false, elapsedMs, evidence: applied }
}

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
  if (payload.length < 65536) {
    const header = Buffer.alloc(4)
    header[0] = 0x82
    header[1] = 126
    header.writeUInt16BE(payload.length, 2)
    return Buffer.concat([header, payload])
  }
  const header = Buffer.alloc(10)
  header[0] = 0x82
  header[1] = 127
  header.writeBigUInt64BE(BigInt(payload.length), 2)
  return Buffer.concat([header, payload])
}

const mime = file => ({
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
}[path.extname(file)] || 'application/octet-stream')

const serveAsset = (request, response, root, prefix) => {
  let relative = request.url?.split('?')[0] || '/'
  relative = relative.slice(prefix.length) || '/'
  if (relative === '/') relative = '/index.html'
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

const closeStreams = () => {
  for (const [socket, timer] of streams) {
    clearInterval(timer)
    streams.delete(socket)
    if (!socket.destroyed && socket.writable) socket.end(Buffer.from([0x88, 0x02, 0x03, 0xe8]))
  }
}

const extractSignedBundle = () => {
  const bundle = readFileSync(path.join(repoRoot, 'docs/evidence/line-crossing-ui/line-crossing.neui'))
  assert.equal(bundle.subarray(0, 8).toString('hex'), '4e45554901000000')
  const manifestLen = bundle.readUInt32LE(8)
  const payloadLen = bundle.readUInt32LE(12)
  const manifest = bundle.subarray(16, 16 + manifestLen)
  const payload = bundle.subarray(16 + manifestLen, 16 + manifestLen + payloadLen)
  rmSync(signedRoot, { recursive: true, force: true })
  mkdirSync(signedRoot, { recursive: true })
  const fileCount = manifest.readUInt16LE(118)
  let cursor = 128
  let offset = 0
  for (let index = 0; index < fileCount; index += 1) {
    const pathLen = manifest.readUInt16LE(cursor)
    const fileLen = manifest.readUInt32LE(cursor + 2)
    const name = manifest.subarray(cursor + 38, cursor + 38 + pathLen).toString('ascii')
    const bytes = payload.subarray(offset, offset + fileLen)
    assert.deepEqual(createHash('sha256').update(bytes).digest(), manifest.subarray(cursor + 6, cursor + 38), `signed asset ${name} digest mismatch`)
    const target = path.join(signedRoot, name)
    mkdirSync(path.dirname(target), { recursive: true })
    writeFileSync(target, bytes)
    cursor += 38 + pathLen
    offset += fileLen
  }
  assert.equal(cursor, manifestLen)
  assert.equal(offset, payloadLen)
}

before(async () => {
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
  assert.ok(frameUnits.every(unit => unit.length > 64))
  extractSignedBundle()

  server = createServer((request, response) => {
    const url = new URL(request.url || '/', 'http://127.0.0.1')
    requests.push(url.pathname)
    response.setHeader('Cache-Control', 'no-store')
    response.setHeader('Content-Security-Policy', `default-src 'self' blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' ws://127.0.0.1:${server.address()?.port}; worker-src 'self' blob:; object-src 'none'; base-uri 'none'`)
    if (url.pathname.startsWith('/production/')) return serveAsset(request, response, productionRoot, '/production')
    if (url.pathname.startsWith('/browser/')) return serveAsset(request, response, browserRoot, '/browser')
    if (url.pathname.startsWith('/signed/')) return serveAsset(request, response, signedRoot, '/signed')
    response.statusCode = 404
    response.end('not found')
  })
  server.on('upgrade', (request, socket) => {
    const key = request.headers['sec-websocket-key']
    if (!streamEnabled || request.url?.split('?')[0] !== '/stream' || typeof key !== 'string') {
      socket.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n')
      socket.destroy()
      return
    }
    const accept = createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64')
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`)
    socket.setNoDelay(true)
    let sequence = 0
    const timer = setInterval(() => {
      if (socket.destroyed || socket.writableEnded || !socket.writable) return
      try {
        socket.write(websocketFrame(frameBuffer(frameUnits[sequence % frameUnits.length], sequence)))
      } catch {
        clearInterval(timer)
        streams.delete(socket)
        socket.destroy()
      }
      sequence += 1
    }, 40)
    streams.set(socket, timer)
    socket.on('error', () => undefined)
    socket.on('close', () => {
      clearInterval(timer)
      streams.delete(socket)
    })
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  serverUrl = `http://127.0.0.1:${server.address().port}`
  browser = await chromium.launch({
    executablePath: chromePath,
    headless: true,
    args: ['--no-sandbox', '--autoplay-policy=no-user-gesture-required'],
  })
})

after(async () => {
  closeStreams()
  await browser?.close()
  await new Promise(resolve => server?.close(() => resolve()))
})

test('production entry reports unavailable capabilities without placeholder data or writes', async () => {
  for (const [label, root] of [['rebuilt production build', '/production/'], ['committed signed bundle content', '/signed/']]) {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, locale: 'en-US' })
    await page.goto(`${serverUrl}${root}`, { waitUntil: 'load' })
    await page.getByTestId('lc-module').waitFor()
    assert.equal(await page.getByTestId('lc-app-state').getAttribute('data-state'), 'unavailable', label)
    assert.equal(await page.getByTestId('lc-video-state').getAttribute('data-state'), 'unavailable', label)
    assert.equal(await page.getByTestId('lc-stats-unavailable').count(), 1, label)
    assert.equal(await page.getByTestId('lc-events-unavailable').count(), 1, label)
    assert.equal(await page.getByTestId('lc-stat-cell').count(), 0, label)
    assert.equal(await page.getByTestId('lc-reset-stats').isDisabled(), true, label)

    await page.getByTestId('lc-tab-config').click()
    await page.getByTestId('lc-config-unavailable').waitFor()
    assert.equal(await page.getByTestId('lc-config-unavailable').count(), 1, label)
    assert.equal(await page.getByTestId('lc-business-enable').count(), 0, label)
    assert.equal(await page.getByTestId('lc-save-config').isDisabled(), true, label)
    assert.equal(await page.evaluate(() => typeof window.__lineCrossingTest), 'undefined', label)

    await page.getByTestId('lc-tab-advanced').click()
    assert.equal(await page.getByTestId('lc-app-settings-unavailable').count(), 1, label)
    assert.equal(await page.getByTestId('lc-host-settings-unavailable').count(), 1, label)
    assert.equal(await page.getByTestId('lc-save-app').isDisabled(), true, label)
    assert.equal(await page.getByTestId('lc-save-host').isDisabled(), true, label)

    await page.getByTestId('lc-tab-realtime').click()
    await page.getByTestId('lc-stats-unavailable').waitFor()
    assert.equal(await page.getByTestId('lc-page-realtime').count(), 1, label)
    await page.close()
  }
})

test('real H.264 playback, line editing, separate saves, reconnect and revoked video grant work offline', async () => {
  streamEnabled = true
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, locale: 'en-US' })
  await page.goto(`${serverUrl}/browser/`, { waitUntil: 'load' })
  await page.getByTestId('lc-module').waitFor()
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-video-state"]')?.getAttribute('data-state') === 'live', null, { timeout: 20000 })
  const playback = await page.locator('#lcVideoPlayer').evaluate(video => ({ width: video.videoWidth, height: video.videoHeight, time: video.currentTime, aspectRatio: video.style.aspectRatio }))
  assert.deepEqual([playback.width, playback.height], [320, 180])
  assert.ok(Math.abs(Number.parseFloat(playback.aspectRatio) - 16 / 9) < 0.00001)
  assert.ok(playback.time > 0)
  assert.equal(await page.getByTestId('lc-track').count(), 1)
  assert.equal(await page.getByTestId('lc-event-class').textContent(), 'person')
  assert.equal(await page.getByTestId('lc-event-list').getByText('IN', { exact: true }).count(), 1)

  await page.getByTestId('lc-reset-stats').click()
  await page.getByTestId('lc-reset-dialog').waitFor()
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().reset)).length, 0)
  await page.locator('[data-testid="lc-reset-dialog"] button').first().click()
  await page.getByTestId('lc-reset-stats').click()
  await page.locator('[data-testid="lc-reset-dialog"] button').last().click()
  await page.waitForFunction(() => window.__lineCrossingTest.getCalls().reset.length === 1)

  await page.locator('[data-testid="lc-line-toolbar"] button').first().click()
  await page.locator('[data-testid="lc-line-toolbar"] button').nth(2).click()
  await page.getByTestId('lc-reset-line-dialog').waitFor()
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().app)).length, 0)
  await page.locator('[data-testid="lc-reset-line-dialog"] button').first().click()
  const endpoint = page.locator('[data-testid="lc-line-endpoint"][data-endpoint="end"]')
  await endpoint.hover()
  const stage = await page.getByTestId('lc-stage').boundingBox()
  assert.ok(stage)
  await page.mouse.down()
  await page.mouse.move(stage.x + stage.width * 0.7, stage.y + stage.height * 0.6, { steps: 6 })
  await page.mouse.up()
  await page.getByTestId('lc-discard').click()
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().app)).length, 0)

  await page.locator('[data-testid="lc-line-toolbar"] button').first().click()
  const activeEndpoint = page.locator('[data-testid="lc-line-endpoint"][data-endpoint="end"]')
  await observeSavePointerEvents(page)
  await activeEndpoint.hover()
  const activeStage = await page.getByTestId('lc-stage').boundingBox()
  assert.ok(activeStage)
  await page.mouse.down()
  await page.mouse.move(activeStage.x + activeStage.width * 0.7, activeStage.y + activeStage.height * 0.6, { steps: 6 })
  await page.mouse.up()
  const beforeLineSave = { phase: 'before-line-save', scenario: 'normal-suite', ...await captureSaveBoundary(page) }
  recordSaveBoundary(beforeLineSave)
  console.log(`LC_SAVE_BEFORE ${JSON.stringify(beforeLineSave)}`)
  assert.equal(beforeLineSave.editMode, true, 'line edit mode must remain active before the apply click')
  assert.equal(beforeLineSave.dirty, true, 'pointer drag must produce a draft before the apply click')
  assert.equal(beforeLineSave.writeAllowed, true, 'fresh write capability must remain available before the apply click')
  assert.ok(beforeLineSave.pointerEvents.some(event => event.type === 'pointerdown' && event.targetTestId === 'lc-line-endpoint'))
  assert.ok(beforeLineSave.pointerEvents.some(event => event.type === 'pointermove' && event.targetTestId === 'lc-line-endpoint'))
  assert.ok(beforeLineSave.pointerEvents.some(event => event.type === 'pointerup' && event.targetTestId === 'lc-line-endpoint'))
  await page.locator('[data-testid="lc-line-toolbar"] button').first().click()
  const afterLineSaveClick = { phase: 'after-save-click', scenario: 'normal-suite', ...await captureSaveBoundary(page) }
  recordSaveBoundary(afterLineSaveClick)
  console.log(`LC_SAVE_AFTER_CLICK ${JSON.stringify(afterLineSaveClick)}`)
  await waitForFirstLineApply(page, 'normal-suite', 'normal-pointer-sequence')
  const lineApply = (await page.evaluate(() => window.__lineCrossingTest.getCalls().app))[0]
  assert.ok(lineApply.candidate.line.x2 >= 680 && lineApply.candidate.line.x2 <= 720)
  assert.ok(lineApply.candidate.line.y2 >= 580 && lineApply.candidate.line.y2 <= 620)
  assert.deepEqual(Object.keys(lineApply.candidate).sort(), [
    'conf_threshold_permille', 'counter_name', 'heat_grid_enable', 'k_confirm', 'line', 'max_dist_permille',
    'max_miss', 'schema', 'target_class_name', 'track_history_k', 'tracks_report_enable', 'window_minutes',
  ].sort())

  await page.getByTestId('lc-tab-config').click()
  await page.getByTestId('lc-page-config').waitFor()
  await page.locator('[data-testid="lc-page-config"] [data-slot="select-trigger"]').click()
  await page.getByRole('option', { name: 'bicycle' }).click()
  await page.getByTestId('lc-save-config').click()
  await page.getByTestId('lc-confirm-dialog').waitFor()
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().app)).length, 1)
  await page.locator('[data-testid="lc-confirm-dialog"] button').last().click()
  await page.waitForFunction(() => window.__lineCrossingTest.getCalls().app.length === 2)
  const targetApply = (await page.evaluate(() => window.__lineCrossingTest.getCalls().app))[1]
  assert.equal(targetApply.candidate.target_class_name, 'bicycle')
  assert.equal(Object.hasOwn(targetApply.candidate, 'mqtt_enabled'), false)
  assert.equal(Object.hasOwn(targetApply.candidate, 'webhook_enabled'), false)
  assert.equal(Object.hasOwn(targetApply.candidate, 'backlog_capacity'), false)

  await page.getByTestId('lc-tab-advanced').click()
  await page.getByTestId('lc-app-window-minutes').locator('input').fill('90')
  await page.getByTestId('lc-save-app').click()
  await page.waitForFunction(() => window.__lineCrossingTest.getCalls().app.length === 3)
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().host)).length, 0)
  await page.getByTestId('lc-host-backlog-capacity').locator('input').fill('64')
  await page.getByTestId('lc-save-host').click()
  await page.waitForFunction(() => window.__lineCrossingTest.getCalls().host.length === 1)
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().app)).length, 3)

  await page.getByTestId('lc-tab-config').click()
  await page.getByTestId('lc-counter-name').fill('Uncommitted draft')
  await page.evaluate(() => window.__lineCrossingTest.revokeConfigWrite())
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-save-config"]')?.disabled === true)
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-counter-name"]')?.value === 'Counter Test')
  assert.equal(await page.getByTestId('lc-counter-name').inputValue(), 'Counter Test')
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().app)).length, 3)

  streamEnabled = false
  closeStreams()
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-video-state"]')?.getAttribute('data-state') === 'reconnecting', null, { timeout: 5000 })
  streamEnabled = true
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-video-state"]')?.getAttribute('data-state') === 'live', null, { timeout: 10000 })
  await page.evaluate(() => window.__lineCrossingTest.revokeVideo())
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-video-state"]')?.getAttribute('data-state') === 'unavailable')
  assert.ok(await page.evaluate(() => window.__lineCrossingTest.getReleasedGrants()) >= 1)
  await page.close()
})

test('unknown outcomes, stale snapshots, session generation changes and worker failures do not replay writes', async () => {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, locale: 'en-US' })
  await page.goto(`${serverUrl}/browser/`, { waitUntil: 'load' })
  await page.getByTestId('lc-tab-config').click()
  await page.getByTestId('lc-counter-name').fill('Unknown outcome draft')
  await page.evaluate(() => window.__lineCrossingTest.setNextOutcome('UNKNOWN'))
  await page.getByTestId('lc-save-config').click()
  await page.getByTestId('lc-save-status').waitFor()
  assert.match(await page.getByTestId('lc-save-status').textContent(), /Outcome unknown/)
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().app)).length, 1)

  await page.evaluate(() => window.__lineCrossingTest.makeAppStale())
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-app-state"]')?.getAttribute('data-state') === 'stale')
  assert.equal(await page.getByTestId('lc-save-config').isDisabled(), true)
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().app)).length, 1)
  await page.close()

  const racePage = await browser.newPage({ viewport: { width: 1280, height: 900 }, locale: 'en-US' })
  await racePage.goto(`${serverUrl}/browser/`, { waitUntil: 'load' })
  await racePage.getByTestId('lc-tab-config').click()
  await racePage.getByTestId('lc-counter-name').fill('Old session draft')
  await racePage.evaluate(() => window.__lineCrossingTest.delayNextApply())
  await racePage.getByTestId('lc-save-config').click()
  await racePage.waitForFunction(() => window.__lineCrossingTest.getCalls().app.length === 1)
  await racePage.evaluate(() => window.__lineCrossingTest.changeSession())
  await racePage.evaluate(() => window.__lineCrossingTest.resolvePendingApply())
  await racePage.waitForFunction(() => document.querySelector('[data-testid="lc-save-status"]')?.textContent?.includes('session changed'))
  assert.equal((await racePage.evaluate(() => window.__lineCrossingTest.getCalls().app)).length, 1)
  await racePage.close()

  const brokenPage = await browser.newPage({ viewport: { width: 1280, height: 900 }, locale: 'en-US' })
  await brokenPage.route('**/videoWorker-*.js', route => route.abort())
  await brokenPage.goto(`${serverUrl}/browser/`, { waitUntil: 'load' })
  await brokenPage.waitForFunction(() => document.querySelector('[data-testid="lc-video-state"]')?.getAttribute('data-state') === 'unavailable', null, { timeout: 10000 })
  assert.equal(await brokenPage.locator('#lcVideoPlayer').evaluate(video => video.currentTime > 0), false)
  await brokenPage.close()
})

test('available business Enable capability never exposes a pause or disable control', async () => {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, locale: 'en-US' })
  await page.goto(`${serverUrl}/browser/`, { waitUntil: 'load' })
  await page.getByTestId('lc-module').waitFor()
  await page.getByTestId('lc-tab-config').click()
  await page.getByTestId('lc-page-config').waitFor()

  await page.evaluate(() => window.__lineCrossingTest.grantEnableControl(false))
  await page.waitForFunction(() => {
    const capability = window.__lineCrossingTest.getState().businessEnable
    return capability.state === 'available' && capability.value === false
  })
  assert.equal(await page.getByTestId('lc-business-enable').count(), 0)
  assert.equal(await page.getByTestId('lc-business-enable-switch').count(), 0)
  assert.equal(await page.getByRole('switch').count(), 0)
  assert.equal(await page.getByRole('checkbox').count(), 0)
  assert.equal(await page.getByText(/pause business|pause counting|disable counting|disable statistics/i).count(), 0)
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().enable)).length, 0)
  assert.equal(await page.getByTestId('lc-counter-name').inputValue(), 'Counter Test')
  await page.close()
})

test('independent App and Host saves keep isolated outcomes across partial failures and pending drafts', async () => {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, locale: 'en-US' })
  await page.goto(`${serverUrl}/browser/`, { waitUntil: 'load' })
  await page.getByTestId('lc-module').waitFor()
  await page.getByTestId('lc-tab-advanced').click()
  await page.getByTestId('lc-page-advanced').waitFor()

  await page.evaluate(() => window.__lineCrossingTest.setNextHostOutcome('UNKNOWN'))
  await page.getByTestId('lc-app-window-minutes').locator('input').fill('100')
  await page.getByTestId('lc-host-backlog-capacity').locator('input').fill('48')
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().app)).length, 0)
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().host)).length, 0)

  await page.getByTestId('lc-save-app').click()
  await page.waitForFunction(() => window.__lineCrossingTest.getCalls().app.length === 1)
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-app-save-status"]')?.textContent === 'Applied')
  assert.equal(await page.evaluate(() => window.__lineCrossingTest.getState().app.value.config.window_minutes), 100)

  await page.getByTestId('lc-save-host').click()
  await page.waitForFunction(() => window.__lineCrossingTest.getCalls().host.length === 1)
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-host-save-status"]')?.textContent === 'Outcome unknown; no automatic retry was sent')
  assert.equal(await page.evaluate(() => window.__lineCrossingTest.getState().hostPolicy.value.config.backlog_capacity), 32)
  assert.equal(await page.evaluate(() => window.__lineCrossingTest.getState().app.value.config.window_minutes), 100)

  await page.evaluate(() => window.__lineCrossingTest.setNextHostOutcome('APPLIED'))
  await page.getByTestId('lc-save-host').click()
  await page.waitForFunction(() => window.__lineCrossingTest.getCalls().host.length === 2)
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-host-save-status"]')?.textContent === 'Applied')
  assert.equal(await page.evaluate(() => window.__lineCrossingTest.getState().hostPolicy.value.config.backlog_capacity), 48)
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().app)).length, 1)

  await page.evaluate(() => window.__lineCrossingTest.setNextHostOutcome('CONFLICT'))
  await page.getByTestId('lc-save-host').click()
  await page.waitForFunction(() => window.__lineCrossingTest.getCalls().host.length === 3)
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-host-save-status"]')?.textContent === 'Conflict; reload the current snapshot')
  assert.equal(await page.evaluate(() => window.__lineCrossingTest.getState().hostPolicy.value.generation), 5)
  assert.equal(await page.evaluate(() => window.__lineCrossingTest.getState().hostPolicy.value.config.backlog_capacity), 48)

  await page.evaluate(() => window.__lineCrossingTest.setNextOutcome('UNKNOWN'))
  await page.getByTestId('lc-app-window-minutes').locator('input').fill('120')
  await page.getByTestId('lc-save-app').click()
  await page.waitForFunction(() => window.__lineCrossingTest.getCalls().app.length === 2)
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-app-save-status"]')?.textContent === 'Outcome unknown; no automatic retry was sent')
  assert.equal(await page.evaluate(() => window.__lineCrossingTest.getState().app.value.config.window_minutes), 100)
  assert.equal(await page.evaluate(() => window.__lineCrossingTest.getState().hostPolicy.value.config.backlog_capacity), 48)

  await page.evaluate(() => window.__lineCrossingTest.setNextOutcome('CONFLICT'))
  await page.getByTestId('lc-save-app').click()
  await page.waitForFunction(() => window.__lineCrossingTest.getCalls().app.length === 3)
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-app-save-status"]')?.textContent === 'Conflict; reload the current snapshot')
  assert.equal(await page.evaluate(() => window.__lineCrossingTest.getState().app.value.config.window_minutes), 100)

  await page.evaluate(() => window.__lineCrossingTest.setNextOutcome('APPLIED'))
  await page.getByTestId('lc-save-app').click()
  await page.waitForFunction(() => window.__lineCrossingTest.getCalls().app.length === 4)
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-app-save-status"]')?.textContent === 'Applied')
  assert.equal(await page.evaluate(() => window.__lineCrossingTest.getState().app.value.config.window_minutes), 120)
  assert.equal(await page.evaluate(() => window.__lineCrossingTest.getState().hostPolicy.value.generation), 5)
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().host)).length, 3)
  assert.equal(await page.evaluate(() => document.querySelector('[data-testid="lc-host-save-status"]')?.textContent), 'Conflict; reload the current snapshot')

  await page.getByTestId('lc-app-window-minutes').locator('input').fill('130')
  await page.evaluate(() => window.__lineCrossingTest.delayNextApply())
  await page.getByTestId('lc-save-app').click()
  await page.waitForFunction(() => window.__lineCrossingTest.getCalls().app.length === 5)
  assert.equal(await page.getByTestId('lc-save-app').isDisabled(), true)
  assert.equal(await page.getByTestId('lc-save-host').isDisabled(), false)

  await page.getByTestId('lc-host-backlog-capacity').locator('input').fill('64')
  await page.evaluate(() => window.__lineCrossingTest.setNextHostOutcome('APPLIED'))
  await page.getByTestId('lc-save-host').click()
  await page.waitForFunction(() => window.__lineCrossingTest.getCalls().host.length === 4)
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-host-save-status"]')?.textContent === 'Applied')
  assert.equal(await page.evaluate(() => window.__lineCrossingTest.getState().hostPolicy.value.config.backlog_capacity), 64)
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().app)).length, 5)

  await page.evaluate(() => window.__lineCrossingTest.resolvePendingApply())
  await page.waitForFunction(() => document.querySelector('[data-testid="lc-app-save-status"]')?.textContent === 'Applied')
  assert.equal(await page.evaluate(() => window.__lineCrossingTest.getState().app.value.config.window_minutes), 130)
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().app)).length, 5)
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().host)).length, 4)
  await page.close()
})

test('line-save diagnostic matrix isolates freshness, fixture observation and pointer-sequence failures', { skip: process.env.LC_SAVE_DIAGNOSTIC_PHASE !== 'matrix' }, async () => {
  const openDiagnosticPage = async scenario => {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, locale: 'en-US' })
    await page.goto(`${serverUrl}/browser/`, { waitUntil: 'load' })
    await page.getByTestId('lc-module').waitFor()
    await page.waitForFunction(() => document.querySelector('[data-testid="lc-video-state"]')?.getAttribute('data-state') === 'live', null, { timeout: 20000 })
    await page.locator('[data-testid="lc-line-toolbar"] button').first().click()
    await observeSavePointerEvents(page)
    return { page, scenario }
  }

  const dragEndpoint = async page => {
    const endpoint = page.locator('[data-testid="lc-line-endpoint"][data-endpoint="end"]')
    await endpoint.hover()
    const stage = await page.getByTestId('lc-stage').boundingBox()
    assert.ok(stage)
    await page.mouse.down()
    await page.mouse.move(stage.x + stage.width * 0.7, stage.y + stage.height * 0.6, { steps: 6 })
    await page.mouse.up()
  }

  const recordBoundary = async (page, phase, scenario, injection) => {
    const evidence = { phase, scenario, injection, ...await captureSaveBoundary(page) }
    recordSaveBoundary(evidence)
    console.log(`LC_SAVE_DIAGNOSTIC ${JSON.stringify(evidence)}`)
    return evidence
  }

  streamEnabled = true

  {
    const { page, scenario } = await openDiagnosticPage('normal-control')
    await dragEndpoint(page)
    const before = await recordBoundary(page, 'before-save', scenario, 'normal-pointer-sequence')
    assert.equal(before.editMode, true)
    assert.equal(before.dirty, true)
    assert.equal(before.writeAllowed, true)
    assert.ok(before.pointerEvents.some(event => event.type === 'pointermove' && event.targetTestId === 'lc-line-endpoint'))
    await page.locator('[data-testid="lc-line-toolbar"] button').first().click()
    await recordBoundary(page, 'after-save-click', scenario, 'normal-pointer-sequence')
    const result = await waitForFirstLineApply(page, scenario, 'normal-pointer-sequence')
    assert.equal(result.timedOut, false)
    assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().app)).length, 1)
    await page.close()
  }

  {
    const { page, scenario } = await openDiagnosticPage('capability-expired-before-apply')
    await dragEndpoint(page)
    await page.evaluate(() => window.__lineCrossingTest.makeAppStale())
    await page.waitForFunction(() => document.querySelector('[data-testid="lc-line-toolbar"] button')?.disabled === true)
    const expired = await recordBoundary(page, 'capability-expired', scenario, 'app-observation-aged-past-freshness')
    assert.ok(expired.appCapabilityAgeMs > capabilityFreshForMs)
    assert.ok(expired.appSnapshotAgeMs > capabilityFreshForMs)
    assert.equal(expired.writeAllowed, false)
    assert.equal(expired.toolbarDisabled, true)
    assert.equal(expired.appWriteCallCount, 0)
    await page.close()
  }

  {
    const { page, scenario } = await openDiagnosticPage('fixture-observation-not-refreshed')
    await dragEndpoint(page)
    const before = await recordBoundary(page, 'fixture-observation-before-wait', scenario, 'no-fixture-refresh')
    const originalObservedAtMs = before.appSnapshot.observedAtMs
    await page.waitForTimeout(Math.max(0, originalObservedAtMs + capabilityFreshForMs + 250 - Date.now()))
    await page.waitForFunction(() => document.querySelector('[data-testid="lc-line-toolbar"] button')?.disabled === true, null, { timeout: 3000 })
    const expired = await recordBoundary(page, 'fixture-observation-expired', scenario, 'no-fixture-refresh')
    assert.equal(expired.appSnapshot.observedAtMs, originalObservedAtMs)
    assert.ok(expired.appSnapshotAgeMs > capabilityFreshForMs)
    assert.equal(expired.writeAllowed, false)
    assert.equal(expired.appWriteCallCount, 0)
    await page.close()
  }

  {
    const { page, scenario } = await openDiagnosticPage('pointer-down-up-without-drag')
    const endpoint = page.locator('[data-testid="lc-line-endpoint"][data-endpoint="end"]')
    await endpoint.hover()
    await page.mouse.down()
    await page.mouse.up()
    const before = await recordBoundary(page, 'before-save', scenario, 'pointer-move-omitted-after-down')
    assert.equal(before.editMode, true)
    assert.equal(before.dirty, false)
    assert.equal(before.writeAllowed, true)
    const downAt = before.pointerEvents.findIndex(event => event.type === 'pointerdown')
    const upAt = before.pointerEvents.findIndex((event, index) => index > downAt && event.type === 'pointerup')
    assert.ok(downAt >= 0 && upAt > downAt)
    assert.equal(before.pointerEvents.slice(downAt + 1, upAt).some(event => event.type === 'pointermove'), false)
    await page.locator('[data-testid="lc-line-toolbar"] button').first().click()
    const afterClick = await recordBoundary(page, 'after-save-click', scenario, 'pointer-move-omitted-after-down')
    assert.equal(afterClick.appWriteCallCount, 0)
    const result = await waitForFirstLineApply(page, scenario, 'pointer-move-omitted-after-down', true)
    assert.equal(result.timedOut, true)
    assert.ok(result.elapsedMs >= 29500)
    assert.match(result.error.message, /Timeout 30000ms exceeded/)
    assert.equal(result.evidence.appWriteCallCount, 0)
    await page.close()
  }

  {
    const { page, scenario } = await openDiagnosticPage('pointer-cancel-before-drag')
    const endpoint = page.locator('[data-testid="lc-line-endpoint"][data-endpoint="end"]')
    await endpoint.hover()
    await page.mouse.down()
    await endpoint.dispatchEvent('pointercancel', { bubbles: true, pointerId: 1, pointerType: 'mouse', isPrimary: true, button: -1 })
    await page.mouse.up()
    const before = await recordBoundary(page, 'before-save', scenario, 'pointer-cancel-before-move')
    assert.equal(before.editMode, true)
    assert.equal(before.dirty, false)
    assert.ok(before.pointerEvents.some(event => event.type === 'pointercancel'))
    await page.locator('[data-testid="lc-line-toolbar"] button').first().click()
    await page.waitForTimeout(250)
    const afterClick = await recordBoundary(page, 'after-save-click', scenario, 'pointer-cancel-before-move')
    assert.equal(afterClick.appWriteCallCount, 0)
    await page.close()
  }
})

test('touch pointer drags the start endpoint as draft only and authorized APPLIED commits it', async () => {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: 'en-US', hasTouch: true })
  const page = await context.newPage()
  await page.goto(`${serverUrl}/browser/`, { waitUntil: 'load' })
  await page.getByTestId('lc-module').waitFor()
  await page.locator('[data-testid="lc-line-toolbar"] button').first().click()
  const startDot = page.locator('[data-testid="lc-line-endpoint"][data-endpoint="start"]')
  await startDot.waitFor()
  await page.evaluate(() => {
    window.__touchPointerSeen = null
    window.addEventListener('pointerdown', event => { window.__touchPointerSeen = event.pointerType }, { capture: true, once: true })
  })
  const stage = await page.getByTestId('lc-stage').boundingBox()
  const dot = await startDot.boundingBox()
  assert.ok(stage && dot)
  const fromX = dot.x + dot.width / 2
  const fromY = dot.y + dot.height / 2
  const toX = stage.x + stage.width * 0.35
  const toY = stage.y + stage.height * 0.65
  const cdp = await context.newCDPSession(page)
  await cdp.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x: fromX, y: fromY, id: 1 }] })
  await cdp.send('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: [{ x: toX, y: toY, id: 1 }] })
  await cdp.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] })
  assert.equal(await page.evaluate(() => window.__touchPointerSeen), 'touch')
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().app)).length, 0)
  assert.equal(await page.evaluate(() => window.__lineCrossingTest.getState().app.value.config.line.x1), 250)
  assert.equal(await page.getByTestId('lc-discard').count(), 1)

  await page.locator('[data-testid="lc-line-toolbar"] button').first().click()
  await page.waitForFunction(() => window.__lineCrossingTest.getCalls().app.length === 1)
  const touchApply = (await page.evaluate(() => window.__lineCrossingTest.getCalls().app))[0]
  const line = touchApply.candidate.line
  assert.ok(line.x1 >= 345 && line.x1 <= 355, `start x ${line.x1}`)
  assert.ok(line.y1 >= 645 && line.y1 <= 655, `start y ${line.y1}`)
  assert.equal(line.x2, 750)
  assert.equal(line.y2, 500)
  assert.ok(line.outside_x >= 492 && line.outside_x <= 502, `outside x ${line.outside_x}`)
  assert.ok(line.outside_y >= 430 && line.outside_y <= 440, `outside y ${line.outside_y}`)
  const cross = (l, o) => (l.x2 - l.x1) * (o.y - l.y1) - (l.y2 - l.y1) * (o.x - l.x1)
  const initial = { x1: 250, y1: 500, x2: 750, y2: 500, outside_x: 500, outside_y: 350 }
  assert.equal(Math.sign(cross(initial, initial)), Math.sign(cross(line, line)))
  assert.equal(await page.evaluate(() => window.__lineCrossingTest.getState().app.value.config.line.x1), line.x1)
  await context.close()
})
