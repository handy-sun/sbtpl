import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

import {
  buildServerInboundTag,
  buildServerLog,
  getLocalIpFromInterfaces,
  normalizeMeta,
  resolveServerIpInput,
  validateProtocolTag,
  PROTOCOL_REGISTRY,
} from '../node/server.js'

const serverScript = path.resolve('node/server.js')

function runServer(...args) {
  return spawnSync(process.execPath, [serverScript, ...args], { encoding: 'utf8' })
}

test('buildServerInboundTag uses protocol and port', () => {
  assert.equal(buildServerInboundTag('vmess', 20086), 'vmess-20086')
  assert.equal(buildServerInboundTag('trojan', 443), 'trojan-443')
  assert.equal(buildServerInboundTag('ss', 20085), 'ss-20085')
})

test('getLocalIpFromInterfaces chooses the first non-internal IPv4 address', () => {
  const interfaces = {
    lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true }],
    eth0: [
      { address: 'fe80::1', family: 'IPv6', internal: false },
      { address: '192.0.2.10', family: 'IPv4', internal: false },
    ],
    wlan0: [{ address: '198.51.100.8', family: 'IPv4', internal: false }],
  }

  assert.equal(getLocalIpFromInterfaces(interfaces), '192.0.2.10')
})

test('resolveServerIpInput auto-detects IP when first setup answer is empty', () => {
  const result = resolveServerIpInput('', '', {
    autoDetectIfEmpty: true,
    detectLocalIp: () => '192.0.2.20',
  })

  assert.deepEqual(result, {
    changed: true,
    ip: '192.0.2.20',
    autoDetected: true,
  })
})

test('resolveServerIpInput keeps existing blank behavior outside first setup', () => {
  const result = resolveServerIpInput('', '203.0.113.5', {
    autoDetectIfEmpty: false,
    detectLocalIp: () => '192.0.2.20',
  })

  assert.deepEqual(result, {
    changed: false,
    ip: '203.0.113.5',
    autoDetected: false,
  })
})

test('normalizeMeta applies default server settings for older metadata', () => {
  const meta = normalizeMeta({
    ip: '203.0.113.5',
    protocols: [{ type: 'vmess' }],
    extra: 'kept',
    settings: { futureSetting: 'kept' },
  })

  assert.equal(meta.extra, 'kept')
  assert.deepEqual(meta.settings, {
    futureSetting: 'kept',
    serverLogTimestamp: false,
    serverLogFile: '',
  })
})

test('normalizeMeta assigns tags to legacy protocols and keeps explicit tags', () => {
  const meta = normalizeMeta({
    protocols: [
      { type: 'vmess', port: 20086, uuid: 'vmess-uuid' },
      { type: 'trojan', port: 443, password: 'trojan-password', tag: 'edge-trojan' },
    ],
  })

  assert.equal(meta.protocols[0].tag, 'vmess-20086')
  assert.equal(meta.protocols[1].tag, 'edge-trojan')
})

test('validateProtocolTag rejects duplicate node tags but permits the current node', () => {
  const protocols = [
    { type: 'vmess', port: 20086, tag: 'edge-a' },
    { type: 'trojan', port: 443, tag: 'edge-b' },
  ]

  assert.equal(validateProtocolTag(' edge-c ', protocols), 'edge-c')
  assert.equal(validateProtocolTag('edge-a', protocols, protocols[0]), 'edge-a')
  assert.throws(() => validateProtocolTag('edge-a', protocols), /tag.*already exists/i)
  assert.throws(() => validateProtocolTag('direct', protocols), /tag.*reserved/i)
  assert.throws(() => validateProtocolTag('proxy', protocols), /tag.*reserved/i)
  assert.throws(() => validateProtocolTag('   ', protocols), /tag.*non-empty/i)
})

test('server add persists custom tags and rejects duplicate tags', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sbtpl-server-tag-test-'))
  const metaPath = path.join(dir, 'meta.json')
  t.after(() => rm(dir, { recursive: true, force: true }))

  assert.equal(runServer('set', '--ip', '203.0.113.10', '--meta', metaPath).status, 0)
  const added = runServer('add', 'vmess', '--tag', 'edge-a', '--meta', metaPath)
  assert.equal(added.status, 0, added.stderr)

  const meta = JSON.parse(await readFile(metaPath, 'utf8'))
  assert.equal(meta.protocols[0].tag, 'edge-a')

  const outputDir = path.join(dir, 'output')
  const generated = runServer('gen', '-o', outputDir, '--meta', metaPath)
  assert.equal(generated.status, 0, generated.stderr)
  const serverConfig = JSON.parse(await readFile(path.join(outputDir, 'server-config.json'), 'utf8'))
  const clientConfig = JSON.parse(await readFile(path.join(outputDir, 'client-config.json'), 'utf8'))
  assert.equal(serverConfig.inbounds[0].tag, 'edge-a')
  assert.ok(clientConfig.outbounds.some(outbound => outbound.tag === 'edge-a'))

  const duplicate = runServer('add', 'trojan', '--domain', 'example.com', '--tag', 'edge-a', '--meta', metaPath)
  assert.notEqual(duplicate.status, 0)
  assert.match(duplicate.stdout + duplicate.stderr, /tag.*already exists/i)
})

test('server generation escapes tag interpolation in the Nix module', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sbtpl-server-tag-nix-test-'))
  const metaPath = path.join(dir, 'meta.json')
  const outputDir = path.join(dir, 'output')
  const tag = 'edge-${builtins.abort "pwn"}'
  t.after(() => rm(dir, { recursive: true, force: true }))

  assert.equal(runServer('set', '--ip', '203.0.113.10', '--meta', metaPath).status, 0)
  assert.equal(runServer('add', 'vmess', '--tag', tag, '--meta', metaPath).status, 0)
  assert.equal(runServer('gen', '-o', outputDir, '--meta', metaPath).status, 0)

  const nixModule = await readFile(path.join(outputDir, 'sing-box-server.nix'), 'utf8')
  assert.doesNotMatch(nixModule, /(?<!\\)\$\{builtins\.abort/)
})

test('buildServerLog maps software settings to server log config', () => {
  assert.deepEqual(buildServerLog({
    serverLogTimestamp: false,
    serverLogFile: '',
  }), {
    level: 'info',
    timestamp: false,
  })

  assert.deepEqual(buildServerLog({
    serverLogTimestamp: true,
    serverLogFile: ' /var/log/sing-box/server.log ',
  }), {
    level: 'info',
    timestamp: true,
    output: '/var/log/sing-box/server.log',
  })
})

test('Trojan buildServerInbound with acme mode uses acme field', () => {
  const entry = { port: 443, password: 'test', tlsMode: 'acme', domain: 'example.com' }
  const inbound = PROTOCOL_REGISTRY.trojan.buildServerInbound(entry)
  assert.equal(inbound.type, 'trojan')
  assert.deepEqual(inbound.tls, {
    enabled: true,
    server_name: 'example.com',
    acme: { domain: ['example.com'] },
  })
})

test('server and client outputs use the persisted protocol tag', () => {
  const entry = { tag: 'edge-vmess', port: 20086, uuid: 'test-uuid' }
  const inbound = PROTOCOL_REGISTRY.vmess.buildServerInbound(entry)
  const bean = PROTOCOL_REGISTRY.vmess.metaToBean(entry, '203.0.113.10')

  assert.equal(inbound.tag, 'edge-vmess')
  assert.equal(bean.name, 'edge-vmess')
})

test('Trojan buildServerInbound with self-signed mode uses certificate paths', () => {
  const entry = { port: 443, password: 'test', tlsMode: 'self-signed', domain: 'example.com' }
  const inbound = PROTOCOL_REGISTRY.trojan.buildServerInbound(entry)
  assert.equal(inbound.type, 'trojan')
  assert.deepEqual(inbound.tls, {
    enabled: true,
    server_name: 'example.com',
    certificate_path: '/etc/sing-box/tls.cer',
    key_path: '/etc/sing-box/tls.key',
  })
})

test('Trojan metaToBean sets allowInsecure for self-signed mode', () => {
  const entrySelfSigned = { port: 443, password: 'test', tlsMode: 'self-signed', domain: 'example.com' }
  const bean1 = PROTOCOL_REGISTRY.trojan.metaToBean(entrySelfSigned, '1.2.3.4')
  assert.equal(bean1.allowInsecure, true)

  const entryAcme = { port: 443, password: 'test', tlsMode: 'acme', domain: 'example.com' }
  const bean2 = PROTOCOL_REGISTRY.trojan.metaToBean(entryAcme, '1.2.3.4')
  assert.equal(bean2.allowInsecure, false)
})
