import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const testRoot = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(testRoot, '../..')
const evidenceRoot = path.join(repoRoot, 'docs/evidence/line-crossing-ui')
const productionRoot = path.join(testRoot, '.build/production')
const collect = directory => readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
  const file = path.join(directory, entry.name)
  return entry.isDirectory() ? collect(file) : [file]
})

const parseNeuiContainer = bundle => {
  assert.equal(bundle.subarray(0, 8).toString('hex'), '4e45554901000000')
  const manifestLen = bundle.readUInt32LE(8)
  const payloadLen = bundle.readUInt32LE(12)
  const manifest = bundle.subarray(16, 16 + manifestLen)
  const fileCount = manifest.readUInt16LE(118)
  const records = []
  let cursor = 128
  for (let index = 0; index < fileCount; index += 1) {
    const pathLen = manifest.readUInt16LE(cursor)
    const fileLen = manifest.readUInt32LE(cursor + 2)
    records.push({
      path: manifest.subarray(cursor + 38, cursor + 38 + pathLen).toString('ascii'),
      file_len: fileLen,
      sha256: manifest.subarray(cursor + 6, cursor + 38).toString('hex'),
    })
    cursor += 38 + pathLen
  }
  assert.equal(cursor, manifestLen)
  return { manifestLen, payloadLen, manifest, records }
}

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

test('committed signed NEUI bundle verifies offline and equals the rebuilt production bundle', () => {
  const bundle = readFileSync(path.join(evidenceRoot, 'line-crossing.neui'))
  const verification = JSON.parse(readFileSync(path.join(evidenceRoot, 'neui-verification.json'), 'utf8'))
  const provenance = JSON.parse(readFileSync(path.join(evidenceRoot, 'line-crossing.neui.provenance.json'), 'utf8'))
  const { manifestLen, payloadLen, manifest, records } = parseNeuiContainer(bundle)
  const tbs = bundle.subarray(0, 16 + manifestLen + payloadLen)
  const bundleSha256 = createHash('sha256').update(bundle).digest('hex')
  const uiTbsSha256 = createHash('sha256').update(tbs).digest('hex')
  assert.equal(bundleSha256, verification.bundle_sha256)
  assert.equal(bundleSha256, provenance.bundle_sha256)
  assert.equal(uiTbsSha256, verification.ui_tbs_sha256)
  assert.equal(uiTbsSha256, provenance.ui_tbs_sha256)
  assert.equal(verification.result, 'PASS')
  assert.equal(verification.native_binding_trusted, true)
  assert.equal(verification.publisher_id, 'test-publisher')
  assert.equal(verification.app_id, 'line-crossing')

  const spki = readFileSync(path.join(testRoot, 'evidence/test-publisher.spki.der'))
  const spkiSha256 = createHash('sha256').update(spki).digest('hex')
  assert.equal(spkiSha256, verification.publisher_key_sha256)
  assert.equal(spkiSha256, provenance.signer_spki_sha256)
  assert.equal(cryptoVerify('sha256', tbs, createPublicKey({ key: spki, format: 'der', type: 'spki' }), bundle.subarray(16 + manifestLen + payloadLen)), true)

  const native = readFileSync(path.join(repoRoot, 'docs/evidence/spec-v3/golden.neapp.v3'))
  const nativeTbsSha256 = createHash('sha256')
    .update(native.subarray(0, 16 + native.readUInt32LE(8) + native.readUInt32LE(12)))
    .digest('hex')
  assert.equal(nativeTbsSha256, verification.native_tbs_sha256)
  assert.equal(nativeTbsSha256, provenance.native_binding.native_tbs_sha256)
  assert.equal(manifest.subarray(80, 112).toString('hex'), nativeTbsSha256)

  const production = collect(productionRoot).map(file => ({
    path: path.relative(productionRoot, file).split(path.sep).join('/'),
    bytes: readFileSync(file),
  }))
  assert.equal(records.length, production.length)
  assert.equal(verification.files.length, production.length)
  assert.equal(provenance.files.length, production.length)
  for (const file of production) {
    const record = records.find(item => item.path === file.path)
    assert.ok(record, `signed bundle is missing rebuilt production file ${file.path}`)
    const listed = verification.files.find(item => item.path === file.path)
    const recorded = provenance.files.find(item => item.path === file.path)
    assert.ok(listed && recorded, `evidence artifacts are missing ${file.path}`)
    const fileSha256 = createHash('sha256').update(file.bytes).digest('hex')
    assert.equal(record.file_len, file.bytes.length, `${file.path} length differs from the signed record`)
    assert.equal(record.sha256, fileSha256, `signed ${file.path} differs from the rebuilt production content`)
    assert.equal(listed.sha256, fileSha256)
    assert.equal(recorded.sha256, fileSha256)
  }
  assert.ok(records.some(record => record.path === 'index.html'))
  const signedEntryJs = records.filter(record => /^assets\/index-.+\.js$/.test(record.path))
  assert.equal(signedEntryJs.length, 1)
})

test('signed bundle provenance records the delivered source commit of the packaged UI', () => {
  const provenance = JSON.parse(readFileSync(path.join(evidenceRoot, 'line-crossing.neui.provenance.json'), 'utf8'))
  const sourceCommit = provenance.source_commit
  assert.match(sourceCommit, /^[0-9a-f]{40}$/)
  assert.equal(spawnSync('git', ['rev-parse', '--verify', `${sourceCommit}^{commit}`], { cwd: repoRoot }).status, 0)
  assert.equal(spawnSync('git', ['merge-base', '--is-ancestor', sourceCommit, 'HEAD'], { cwd: repoRoot }).status, 0)
  assert.equal(spawnSync('git', ['diff', '--quiet', sourceCommit, 'HEAD', '--',
    'apps/line-crossing/ui',
    'tests/line-crossing-ui/src',
    'tests/line-crossing-ui/browser-runner',
    'tests/line-crossing-ui/package.sh',
    'tests/line-crossing-ui/browser.test.mjs',
    'tests/line-crossing-ui/contract.test.mjs',
  ], { cwd: repoRoot }).status, 0)
})
