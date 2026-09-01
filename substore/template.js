import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import sharedTemplate from './template.base.json' with { type: 'json' }

const templateDirectory = path.dirname(fileURLToPath(import.meta.url))

function clone(value) {
  return JSON.parse(JSON.stringify(value))
}

function createDns(config, mode) {
  if (mode === 'fakeip') return

  config.dns.servers = config.dns.servers.filter(server => server.tag !== 'dns_fakeip')
  const fakeipRule = config.dns.rules.find(rule => rule.server === 'dns_fakeip')
  if (fakeipRule) fakeipRule.server = 'dns_proxy'
}

function createRoute(config, mode) {
  if (mode === 'fakeip') return

  if (mode === 'real-dns') {
    config.route.rules = config.route.rules.filter((_, index) => index !== 5)
    return
  }

  if (mode === 'real-dns-nosniff') {
    config.route.rules = [
      config.route.rules[2],
      config.route.rules[4],
      ...config.route.rules.slice(6),
    ]
    return
  }

  throw new Error(`unknown template mode: ${mode}`)
}

/**
 * Build one of the supported sing-box templates from the shared JSON source.
 *
 * The base source uses the current sing-box schema. Mode-specific changes are
 * applied to a fresh clone so generated artifacts cannot mutate that source.
 *
 * @param {'fakeip'|'real-dns'|'real-dns-nosniff'} mode
 * @returns {object}
 */
function createTemplate(mode = 'fakeip') {
  const config = clone(sharedTemplate)
  createDns(config, mode)
  createRoute(config, mode)
  return config
}

async function writeTemplates() {
  const files = {
    'template.json': createTemplate('fakeip'),
    'real-dns.json': createTemplate('real-dns'),
    'real-dns-nosniff.json': createTemplate('real-dns-nosniff'),
  }

  await Promise.all(Object.entries(files).map(([name, config]) =>
    fs.writeFile(
      path.join(templateDirectory, name),
      `${JSON.stringify(config, null, 2)}\n`,
      'utf8',
    )))
}

const isMainModule = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)

if (isMainModule && process.argv.includes('--write')) {
  await writeTemplates()
}

export { createTemplate, writeTemplates }
