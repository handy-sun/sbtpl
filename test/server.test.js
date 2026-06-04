import test from 'node:test'
import assert from 'node:assert/strict'

import {
  getLocalIpFromInterfaces,
  resolveServerIpInput,
} from '../node/server.js'

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
