import assert from 'node:assert/strict'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const testRoot = path.dirname(fileURLToPath(import.meta.url))
const productionRoot = path.join(testRoot, '.build/production')
const collect = directory => readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
  const file = path.join(directory, entry.name)
  return entry.isDirectory() ? collect(file) : [file]
})

test('production bundle stays inside the NEUI v1 asset envelope', () => {
  const files = collect(productionRoot).map(file => ({ path: path.relative(productionRoot, file).split(path.sep).join('/'), bytes: readFileSync(file) }))
  assert.ok(files.length <= 64)
  assert.ok(files.every(file => file.bytes.length <= 1024 * 1024))
  assert.ok(files.reduce((total, file) => total + file.bytes.length, 0) <= 2 * 1024 * 1024)
  assert.ok(files.some(file => file.path.endsWith('videoWorker-CwSEKqUk.js')))
  assert.ok(files.some(file => file.path.endsWith('websocket-init-yiJ-u6et.js')))
  assert.ok(files.some(file => file.path === 'assets/jmuxer.min.js'))
  assert.ok(files.some(file => file.path.startsWith('assets/FileSaver.min-') && file.path.endsWith('.js')))
  const html = readFileSync(path.join(productionRoot, 'index.html'), 'utf8')
  assert.match(html, /\.\/assets\//)
  assert.doesNotMatch(html, /["'=]\s?\/(?:libs|assets)\//)
})

test('production source and bundle contain no legacy admin or root media routes', () => {
  const appSourceRoot = path.resolve(testRoot, '../../apps/line-crossing/ui/src')
  const paths = collect(appSourceRoot)
  const source = paths.map(file => readFileSync(file, 'utf8')).join('\n')
  const bundle = collect(productionRoot).map(file => readFileSync(file)).filter(value => value.length < 1024 * 1024).map(value => value.toString('utf8')).join('\n')
  const forbidden = ['/api/v1/apps/line-counting', 'deviceTool', 'ws:8081/stream', '/libs/jmuxer.min.js', '/libs/FileSaver.min.js', 'host_admin_session']
  for (const token of forbidden) {
    assert.equal(source.includes(token), false, `source contains ${token}`)
    assert.equal(bundle.includes(token), false, `bundle contains ${token}`)
  }
  const worker = readFileSync(path.join(productionRoot, 'assets/videoWorker-CwSEKqUk.js'), 'utf8')
  assert.match(worker, /new URL\(['"]\.\/jmuxer\.min\.js['"],self\.location\.href\)/)
  assert.equal(existsSync(path.join(productionRoot, 'assets/jmuxer.min.js')), true)
  const assetNames = collect(productionRoot).map(file => path.relative(productionRoot, file).split(path.sep).join('/'))
  assert.ok(assetNames.every(name => /^[\x00-\x7F]+$/.test(name)))
})
