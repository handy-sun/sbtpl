import test from 'node:test'
import assert from 'node:assert/strict'

import {
  buildServerInboundTag,
  buildServerLog,
  getLocalIpFromInterfaces,
  normalizeMeta,
  resolveServerIpInput,
  PROTOCOL_REGISTRY,
} from '../node/server.js'

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
