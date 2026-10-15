import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { spawnSync } from 'node:child_process'
import { createReadStream, existsSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import test, { after, before } from 'node:test'
import { chromium } from './browser-runner/node_modules/playwright-core/index.mjs'
import { fileURLToPath } from 'node:url'

const testRoot = path.dirname(fileURLToPath(import.meta.url))
const buildRoot = path.join(testRoot, '.build')
const productionRoot = path.join(buildRoot, 'production')
const browserRoot = path.join(buildRoot, 'browser')
const h264Path = path.join(buildRoot, 'line-crossing-test.h264')
const chromePath = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
let browser
let server
let serverUrl
let streamEnabled = true
let frameUnits = []
const streams = new Map()
const requests = []

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

before(async () => {
  assert.equal(existsSync(chromePath), true, 'Google Chrome is required for the offline browser fixture')
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

  server = createServer((request, response) => {
    const url = new URL(request.url || '/', 'http://127.0.0.1')
    requests.push(url.pathname)
    response.setHeader('Cache-Control', 'no-store')
    response.setHeader('Content-Security-Policy', `default-src 'self' blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' ws://127.0.0.1:${server.address()?.port}; worker-src 'self' blob:; object-src 'none'; base-uri 'none'`)
    if (url.pathname.startsWith('/production/')) return serveAsset(request, response, productionRoot, '/production')
    if (url.pathname.startsWith('/browser/')) return serveAsset(request, response, browserRoot, '/browser')
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
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, locale: 'en-US' })
  await page.goto(`${serverUrl}/production/`, { waitUntil: 'load' })
  await page.getByTestId('lc-module').waitFor()
  assert.equal(await page.getByTestId('lc-app-state').getAttribute('data-state'), 'unavailable')
  assert.equal(await page.getByTestId('lc-video-state').getAttribute('data-state'), 'unavailable')
  assert.equal(await page.getByTestId('lc-stats-unavailable').count(), 1)
  assert.equal(await page.getByTestId('lc-events-unavailable').count(), 1)
  assert.equal(await page.getByTestId('lc-stat-cell').count(), 0)

  await page.getByTestId('lc-tab-config').click()
  assert.equal(await page.getByTestId('lc-config-unavailable').count(), 1)
  assert.equal(await page.getByTestId('lc-save-config').isDisabled(), true)
  await page.getByTestId('lc-tab-advanced').click()
  assert.equal(await page.getByTestId('lc-app-settings-unavailable').count(), 1)
  assert.equal(await page.getByTestId('lc-host-settings-unavailable').count(), 1)
  assert.equal(await page.getByTestId('lc-save-app').isDisabled(), true)
  assert.equal(await page.getByTestId('lc-save-host').isDisabled(), true)
  await page.close()
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
  const stage = await page.getByTestId('lc-stage').boundingBox()
  const endpoint = page.locator('[data-testid="lc-line-endpoint"][data-endpoint="end"]')
  const endpointBox = await endpoint.boundingBox()
  assert.ok(stage && endpointBox)
  await page.mouse.move(endpointBox.x + endpointBox.width / 2, endpointBox.y + endpointBox.height / 2)
  await page.mouse.down()
  await page.mouse.move(stage.x + stage.width * 0.7, stage.y + stage.height * 0.6, { steps: 6 })
  await page.mouse.up()
  await page.getByTestId('lc-discard').click()
  assert.equal((await page.evaluate(() => window.__lineCrossingTest.getCalls().app)).length, 0)

  await page.locator('[data-testid="lc-line-toolbar"] button').first().click()
  const activeEndpoint = await page.locator('[data-testid="lc-line-endpoint"][data-endpoint="end"]').boundingBox()
  const activeStage = await page.getByTestId('lc-stage').boundingBox()
  await page.mouse.move(activeEndpoint.x + activeEndpoint.width / 2, activeEndpoint.y + activeEndpoint.height / 2)
  await page.mouse.down()
  await page.mouse.move(activeStage.x + activeStage.width * 0.7, activeStage.y + activeStage.height * 0.6, { steps: 6 })
  await page.mouse.up()
  await page.locator('[data-testid="lc-line-toolbar"] button').first().click()
  await page.waitForFunction(() => window.__lineCrossingTest.getCalls().app.length === 1)
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
