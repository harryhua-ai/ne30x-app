import path from 'node:path'
import { existsSync, mkdirSync, rmdirSync, symlinkSync, unlinkSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import preact from '@preact/preset-vite'
import tailwindcss from '@tailwindcss/vite'
import { build } from 'vite'

const runnerRoot = path.dirname(fileURLToPath(import.meta.url))
const testRoot = path.dirname(runnerRoot)
const repoRoot = path.resolve(testRoot, '../..')
const appRoot = path.join(repoRoot, 'apps/line-crossing/ui')
const outputRoot = path.join(testRoot, '.build')
const runnerModules = path.join(runnerRoot, 'node_modules')
const testModules = path.join(testRoot, 'node_modules')
const appNodeModules = path.join(appRoot, 'node_modules')
const packageAlias = (name) => ({ find: name, replacement: path.join(runnerModules, name) })
const aliases = [
  { find: /^react-dom\/test-utils$/, replacement: path.join(runnerModules, 'preact/test-utils') },
  { find: /^react-dom$/, replacement: path.join(runnerModules, 'preact/compat') },
  { find: /^react\/jsx-runtime$/, replacement: path.join(runnerModules, 'preact/jsx-runtime') },
  { find: /^react\/jsx-dev-runtime$/, replacement: path.join(runnerModules, 'preact/jsx-runtime') },
  { find: /^react$/, replacement: path.join(runnerModules, 'preact/compat') },
  { find: 'preact/compat', replacement: path.join(runnerModules, 'preact/compat') },
  { find: 'preact/hooks', replacement: path.join(runnerModules, 'preact/hooks') },
  { find: /^preact(\/.*)?$/, replacement: `${path.join(runnerModules, 'preact')}$1` },
  { find: /^@lingui\/core$/, replacement: path.join(testModules, '@lingui/core') },
  { find: /^@lingui\/react$/, replacement: path.join(testModules, '@lingui/react') },
  ...[
    '@radix-ui/react-label',
    '@radix-ui/react-select',
    '@radix-ui/react-slot',
    '@radix-ui/react-switch',
    'class-variance-authority',
    'clsx',
    'lucide-react',
    'sonner',
    'tailwind-merge',
  ].map(packageAlias),
  { find: '@', replacement: path.join(appRoot, 'src') },
]
const shared = {
  base: './',
  plugins: [preact({ reactAliasesEnabled: false }), tailwindcss()],
  resolve: { alias: aliases, dedupe: ['preact'] },
  define: { 'process.env.NODE_ENV': JSON.stringify('production') },
  build: { target: 'es2022', assetsInlineLimit: 0, sourcemap: false, worker: { format: 'iife' } },
}

if (existsSync(appNodeModules)) throw new Error('App dependency directory already exists')
mkdirSync(appNodeModules)
symlinkSync(path.join(runnerModules, 'tailwindcss'), path.join(appNodeModules, 'tailwindcss'), 'dir')
try {
  await build({
    ...shared,
    root: appRoot,
    publicDir: path.join(appRoot, 'public'),
    build: { ...shared.build, outDir: path.join(outputRoot, 'production'), emptyOutDir: true },
  })

  await build({
    ...shared,
    root: testRoot,
    publicDir: path.join(appRoot, 'public'),
    build: { ...shared.build, outDir: path.join(outputRoot, 'browser'), emptyOutDir: true },
  })
} finally {
  unlinkSync(path.join(appNodeModules, 'tailwindcss'))
  rmdirSync(appNodeModules)
}
