import test from 'node:test'
import assert from 'node:assert/strict'

import {
  buildServerInboundTag,
  buildServerLog,
  getLocalIpFromInterfaces,
  normalizeMeta,
  resolveServerIpInput,
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
