import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const projectRoot = path.resolve('.')
const baseScript = path.join(projectRoot, 'node/base.js')

async function generateConfig(t, subscription, extraArgs = []) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sbtpl-singbox12-test-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  const output = path.join(dir, 'config.json')
  const result = spawnSync(process.execPath, [
    baseScript,
    '--subscribe-link', subscription,
    '--policy-filter', '@🌐Proxy',
    '--output-file', output,
    ...extraArgs,
  ], { cwd: projectRoot, encoding: 'utf8' })

  assert.equal(result.status, 0, result.stderr || result.stdout)
  return JSON.parse(await readFile(output, 'utf8'))
}

test('WireGuard subscriptions generate an endpoint instead of the legacy outbound', async (t) => {
  const config = await generateConfig(
    t,
    'wg://cHJpdmF0ZS1rZXk=@198.51.100.1:51820?public_key=cHVibGljLWtleQ%3D%3D&address=10.0.0.2%2F32#wireguard-test',
  )

  assert.equal(config.outbounds.some(outbound => outbound.type === 'wireguard'), false)
  assert.deepEqual(config.endpoints, [{
    type: 'wireguard',
    tag: 'wireguard-test',
    mtu: 1420,
    address: ['10.0.0.2/32'],
    private_key: 'cHJpdmF0ZS1rZXk=',
    peers: [{
      address: '198.51.100.1',
      port: 51820,
      public_key: 'cHVibGljLWtleQ==',
      allowed_ips: ['0.0.0.0/0', '::/0'],
    }],
  }])
})

test('Hysteria v1 subscriptions use the 1.12 field names', async (t) => {
  const config = await generateConfig(
    t,
    'hysteria://example.com:443?auth=test&peer=example.com#hysteria-test',
  )
  const outbound = config.outbounds.find(item => item.tag === 'hysteria-test')

  assert.equal(outbound.disable_mtu_discovery, false)
  assert.equal(Object.hasOwn(outbound, 'disable_path_mtu_discovery'), false)
  assert.equal(Object.hasOwn(outbound, 'stream_receive_window'), false)
  assert.equal(Object.hasOwn(outbound, 'connection_receive_window'), false)
})

test('--icmp does not emit the 1.13 icmp network rule', async (t) => {
  const config = await generateConfig(
    t,
    'hysteria://example.com:443?auth=test&peer=example.com#hysteria-test',
    ['--tun', '--icmp'],
  )

  assert.equal(config.route.rules.some(rule => rule.network === 'icmp'), false)
  assert.equal(config.route.rules[0].action, 'sniff')
})

test('Sub-Store moves legacy WireGuard outbounds to endpoints', async () => {
  const template = await readFile(path.join(projectRoot, 'substore/template.json'), 'utf8')
  const scriptUrl = pathToFileURL(path.join(projectRoot, 'substore/substore.js')).href
  const wireGuard = {
    type: 'wireguard',
    tag: 'wireguard-test',
    server: '198.51.100.1',
    server_port: 51820,
    local_address: ['10.0.0.2/32'],
    private_key: 'private-key',
    peer_public_key: 'public-key',
    mtu: 1420,
  }
  const source = `
    globalThis.$arguments = ${JSON.stringify({
      type: 'subscription',
      name: 'test',
      outbound: '@🌐Proxy',
    })};
    globalThis.$content = ${JSON.stringify(template)};
    globalThis.$files = [];
    globalThis.produceArtifact = async () => [${JSON.stringify(wireGuard)}];
    await import(${JSON.stringify(scriptUrl)});
    process.stdout.write('RESULT:' + globalThis.$content);
  `
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', source], {
    cwd: projectRoot,
    encoding: 'utf8',
  })

  assert.equal(result.status, 0, result.stderr || result.stdout)
  const config = JSON.parse(result.stdout.slice(result.stdout.lastIndexOf('RESULT:') + 7))
  assert.equal(config.outbounds.some(outbound => outbound.type === 'wireguard'), false)
  assert.equal(config.endpoints[0].peers[0].public_key, 'public-key')
  assert.equal(Object.hasOwn(config, 'http_clients'), false)
  assert.equal(config.route.rule_set[0].download_detour, '🎯Direct')
})

test('Sub-Store converts 1.14 Hysteria v1 QUIC fields back to 1.12 names', async () => {
  const template = await readFile(path.join(projectRoot, 'substore/template.json'), 'utf8')
  const scriptUrl = pathToFileURL(path.join(projectRoot, 'substore/substore.js')).href
  const hysteria = {
    type: 'hysteria',
    tag: 'hysteria-test',
    server: 'example.com',
    server_port: 443,
    disable_path_mtu_discovery: true,
    stream_receive_window: '1 MiB',
    connection_receive_window: '2 MiB',
  }
  const source = `
    globalThis.$arguments = ${JSON.stringify({
      type: 'subscription',
      name: 'test',
      outbound: '@🌐Proxy',
    })};
    globalThis.$content = ${JSON.stringify(template)};
    globalThis.$files = [];
    globalThis.produceArtifact = async () => [${JSON.stringify(hysteria)}];
    await import(${JSON.stringify(scriptUrl)});
    process.stdout.write('RESULT:' + globalThis.$content);
  `
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', source], {
    cwd: projectRoot,
    encoding: 'utf8',
  })

  assert.equal(result.status, 0, result.stderr || result.stdout)
  const config = JSON.parse(result.stdout.slice(result.stdout.lastIndexOf('RESULT:') + 7))
  const outbound = config.outbounds.find(item => item.tag === 'hysteria-test')

  assert.equal(outbound.disable_mtu_discovery, true)
  assert.equal(outbound.recv_window_conn, 1048576)
  assert.equal(outbound.recv_window, 2097152)
  assert.equal(Object.hasOwn(outbound, 'disable_path_mtu_discovery'), false)
  assert.equal(Object.hasOwn(outbound, 'stream_receive_window'), false)
  assert.equal(Object.hasOwn(outbound, 'connection_receive_window'), false)
})
