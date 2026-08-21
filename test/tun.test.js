import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import os from 'node:os'
import path from 'node:path'

const projectRoot = path.resolve('.')
const baseScript = path.join(projectRoot, 'node/base.js')
const subscription = 'vless://00000000-0000-4000-8000-000000000000@example.com:443?security=tls#test'

async function generateTunConfig(t, extraArgs = []) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sbtpl-tun-test-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  const output = path.join(dir, 'config.json')
  const result = spawnSync(process.execPath, [
    baseScript,
    '--subscribe-link', subscription,
    '--policy-filter', '@🌐Proxy',
    '--tun',
    '--linux',
    ...extraArgs,
    '--output-file', output,
  ], { cwd: projectRoot, encoding: 'utf8' })

  assert.equal(result.status, 0, result.stderr || result.stdout)
  const config = JSON.parse(await readFile(output, 'utf8'))
  return config.inbounds.find(inbound => inbound.type === 'tun')
}

test('Linux TUN defaults to IPv4-only addresses', async (t) => {
  const tun = await generateTunConfig(t)

  assert.deepEqual(tun.address, ['172.19.0.1/30'])
  assert.ok(tun.route_exclude_address.includes('255.255.255.255/32'))
})

test('--ipv6 opts Linux TUN into an IPv6 address', async (t) => {
  const tun = await generateTunConfig(t, ['--ipv6'])

  assert.deepEqual(tun.address, [
    '172.19.0.1/30',
    'fdfe:dcba:9876::1/126',
  ])
})
