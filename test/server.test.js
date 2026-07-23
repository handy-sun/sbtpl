import test from 'node:test'
import assert from 'node:assert/strict'

import {
  buildServerInboundTag,
  buildServerLog,
  getLocalIpFromInterfaces,
  importServerConfig,
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
    serverLogLevel: 'info',
    serverLogTimestamp: false,
    serverLogFile: '',
  })
})

test('normalizeMeta preserves non-empty server log levels and defaults invalid values', () => {
  assert.equal(normalizeMeta({ settings: { serverLogLevel: ' warn ' } }).settings.serverLogLevel, 'warn')

  for (const serverLogLevel of ['', '   ', null, 123]) {
    assert.equal(normalizeMeta({ settings: { serverLogLevel } }).settings.serverLogLevel, 'info')
  }
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
    serverLogLevel: 'warn',
    serverLogTimestamp: true,
    serverLogFile: ' /var/log/sing-box/server.log ',
  }), {
    level: 'warn',
    timestamp: true,
    output: '/var/log/sing-box/server.log',
  })
})

test('importServerConfig replaces supported protocols and log settings while preserving unrelated metadata', () => {
  const config = {
    log: {
      level: 'warn',
      timestamp: true,
      output: '/var/log/sing-box/server.log',
    },
    inbounds: [
      {
        type: 'vmess',
        listen_port: 20086,
        users: [{ uuid: '11111111-2222-3333-4444-555555555555' }],
      },
      {
        type: 'trojan',
        listen_port: 443,
        users: [{ password: 'trojan-secret' }],
        tls: {
          enabled: true,
          server_name: 'example.com',
          certificate_path: '/srv/tls/server.crt',
          key_path: '/srv/tls/server.key',
        },
      },
      {
        type: 'shadowsocks',
        listen_port: 20085,
        method: '2022-blake3-aes-256-gcm',
        password: 'shadowsocks-secret',
      },
      {
        type: 'http',
        listen_port: 8080,
      },
    ],
  }
  const currentMeta = {
    ip: '203.0.113.10',
    protocols: [{ type: 'vmess', port: 1, uuid: 'old-uuid' }],
    settings: {
      serverLogLevel: 'error',
      serverLogTimestamp: false,
      serverLogFile: '/tmp/old.log',
      futureSetting: 'kept',
    },
    extra: 'kept',
  }

  const result = importServerConfig(config, currentMeta)

  assert.deepEqual(result.meta.protocols, [
    {
      type: 'vmess',
      port: 20086,
      uuid: '11111111-2222-3333-4444-555555555555',
    },
    {
      type: 'trojan',
      port: 443,
      password: 'trojan-secret',
      tlsMode: 'self-signed',
      domain: 'example.com',
      certificatePath: '/srv/tls/server.crt',
      keyPath: '/srv/tls/server.key',
    },
    {
      type: 'ss',
      port: 20085,
      method: '2022-blake3-aes-256-gcm',
      password: 'shadowsocks-secret',
    },
  ])
  assert.equal(result.meta.ip, '203.0.113.10')
  assert.equal(result.meta.extra, 'kept')
  assert.deepEqual(result.meta.settings, {
    serverLogLevel: 'warn',
    serverLogTimestamp: true,
    serverLogFile: '/var/log/sing-box/server.log',
    futureSetting: 'kept',
  })
  assert.equal(result.warnings.length, 1)
  assert.match(result.warnings[0], /inbound 3/i)
  assert.match(result.warnings[0], /http/i)
})

test('importServerConfig rejects duplicate supported protocol types', () => {
  const config = {
    inbounds: [
      { type: 'shadowsocks', listen_port: 10001, method: 'aes-256-gcm', password: 'first-secret' },
      { type: 'shadowsocks', listen_port: 10002, method: 'aes-128-gcm', password: 'second-secret' },
    ],
  }

  assert.throws(
    () => importServerConfig(config, {}),
    /inbound 1.*duplicate.*shadowsocks/i,
  )
})

test('importServerConfig rejects malformed or missing credentials without exposing values', () => {
  const cases = [
    {
      config: {
        inbounds: [{
          type: 'vmess',
          listen_port: 20086,
          users: [{ uuid: '' }],
        }],
      },
      field: /uuid/i,
      secret: '',
    },
    {
      config: {
        inbounds: [{
          type: 'trojan',
          listen_port: 443,
          users: [{ password: { value: 'credential-must-not-leak' } }],
          tls: {
            certificate_path: '/srv/tls/server.crt',
            key_path: '/srv/tls/server.key',
          },
        }],
      },
      field: /password/i,
      secret: 'credential-must-not-leak',
    },
  ]

  for (const { config, field, secret } of cases) {
    assert.throws(() => importServerConfig(config, {}), (error) => {
      assert.match(error.message, /inbound 0/i)
      assert.match(error.message, field)
      if (secret) assert.doesNotMatch(error.message, new RegExp(secret))
      return true
    })
  }
})

test('importServerConfig rejects configs without supported inbounds', () => {
  assert.throws(
    () => importServerConfig({ inbounds: [{ type: 'http', password: 'not-a-warning' }] }, {}),
    /no supported inbounds/i,
  )
})

test('importServerConfig treats unusual inbound types as unsupported without leaking nested values', () => {
  const result = importServerConfig({
    inbounds: [
      { type: '__proto__', password: 'prototype-secret' },
      { type: { value: 'nested-secret' }, password: 'another-secret' },
      {
        type: 'vmess',
        listen_port: 20086,
        users: [{ uuid: '11111111-2222-3333-4444-555555555555' }],
      },
    ],
  }, {})

  assert.equal(result.warnings.length, 2)
  assert.match(result.warnings[0], /inbound 0.*__proto__/i)
  assert.match(result.warnings[1], /inbound 1.*object/i)
  assert.doesNotMatch(result.warnings.join('\n'), /prototype-secret|nested-secret|another-secret/)
})

test('importServerConfig maps ACME Trojan domain from server_name or the first valid ACME domain', () => {
  const fromServerName = importServerConfig({
    inbounds: [{
      type: 'trojan',
      listen_port: 443,
      users: [{ password: 'trojan-secret' }],
      tls: {
        enabled: true,
        server_name: 'server-name.example',
        acme: { domain: ['acme.example'] },
      },
    }],
  }, {})
  const fromAcmeDomain = importServerConfig({
    inbounds: [{
      type: 'trojan',
      listen_port: 8443,
      users: [{ password: 'trojan-secret' }],
      tls: {
        enabled: true,
        acme: { domain: ['', 'first.example', 'second.example'] },
      },
    }],
  }, {})

  assert.deepEqual(fromServerName.meta.protocols[0], {
    type: 'trojan',
    port: 443,
    password: 'trojan-secret',
    tlsMode: 'acme',
    domain: 'server-name.example',
  })
  assert.deepEqual(fromAcmeDomain.meta.protocols[0], {
    type: 'trojan',
    port: 8443,
    password: 'trojan-secret',
    tlsMode: 'acme',
    domain: 'first.example',
  })
})

test('importServerConfig validates Trojan server_name whenever it is present', () => {
  const tlsCases = [
    {
      enabled: true,
      server_name: 123,
      acme: { domain: ['acme.example'] },
    },
    {
      enabled: true,
      server_name: '   ',
      certificate_path: '/srv/tls/server.crt',
      key_path: '/srv/tls/server.key',
    },
  ]

  for (const tls of tlsCases) {
    assert.throws(() => importServerConfig({
      inbounds: [{
        type: 'trojan',
        listen_port: 443,
        users: [{ password: 'trojan-secret' }],
        tls,
      }],
    }, {}), /inbound 0.*tls\.server_name.*non-empty string/i)
  }
})

test('importServerConfig validates ACME domain arrays even with a valid server_name', () => {
  const invalidDomains = [
    'acme.example',
    [],
    [null, '   '],
  ]

  for (const domain of invalidDomains) {
    assert.throws(() => importServerConfig({
      inbounds: [{
        type: 'trojan',
        listen_port: 443,
        users: [{ password: 'trojan-secret' }],
        tls: {
          enabled: true,
          server_name: 'server-name.example',
          acme: { domain },
        },
      }],
    }, {}), /inbound 0.*tls\.acme\.domain/i)
  }
})

test('importServerConfig requires Trojan tls.enabled to be boolean true', () => {
  const tlsCases = [
    { acme: { domain: ['missing.example'] } },
    { enabled: null, acme: { domain: ['null.example'] } },
    { enabled: 1, acme: { domain: ['number.example'] } },
    { enabled: 'true', acme: { domain: ['string.example'] } },
  ]

  for (const tls of tlsCases) {
    assert.throws(() => importServerConfig({
      inbounds: [{
        type: 'trojan',
        listen_port: 443,
        users: [{ password: 'trojan-secret' }],
        tls,
      }],
    }, {}), /inbound 0.*tls\.enabled.*true/i)
  }
})

test('importServerConfig validates root, inbound, TLS, and log shapes', () => {
  const validVmess = {
    type: 'vmess',
    listen_port: 20086,
    users: [{ uuid: '11111111-2222-3333-4444-555555555555' }],
  }
  const invalidCases = [
    { config: null, message: /root.*object/i },
    { config: [], message: /root.*object/i },
    { config: {}, message: /inbounds.*array/i },
    { config: { inbounds: [{ ...validVmess, listen_port: 0 }] }, message: /inbound 0.*listen_port/i },
    { config: { inbounds: [{ ...validVmess, users: [] }] }, message: /inbound 0.*users/i },
    {
      config: {
        inbounds: [{
          type: 'shadowsocks', listen_port: 20085, method: '', password: 'secret',
        }],
      },
      message: /inbound 0.*method/i,
    },
    {
      config: {
        inbounds: [{
          type: 'trojan', listen_port: 443, users: [{ password: 'secret' }],
          tls: { enabled: false, acme: { domain: ['example.com'] } },
        }],
      },
      message: /inbound 0.*tls.*enabled/i,
    },
    {
      config: {
        inbounds: [{
          type: 'trojan', listen_port: 443, users: [{ password: 'secret' }],
          tls: {
            enabled: true,
            acme: { domain: ['example.com'] },
            certificate_path: '/srv/tls/server.crt',
            key_path: '/srv/tls/server.key',
          },
        }],
      },
      message: /inbound 0.*mixed.*tls/i,
    },
    { config: { log: null, inbounds: [validVmess] }, message: /log.*object/i },
    { config: { log: { level: '' }, inbounds: [validVmess] }, message: /log\.level/i },
    { config: { log: { timestamp: 'true' }, inbounds: [validVmess] }, message: /log\.timestamp/i },
    { config: { log: { output: false }, inbounds: [validVmess] }, message: /log\.output/i },
  ]

  for (const { config, message } of invalidCases) {
    assert.throws(() => importServerConfig(config, {}), message)
  }
})

test('importServerConfig defaults absent log settings instead of retaining old values', () => {
  const result = importServerConfig({
    inbounds: [{
      type: 'shadowsocks',
      listen_port: 20085,
      method: 'aes-256-gcm',
      password: 'secret',
    }],
  }, {
    settings: {
      serverLogLevel: 'error',
      serverLogTimestamp: true,
      serverLogFile: '/tmp/old.log',
      futureSetting: 'kept',
    },
  })

  assert.deepEqual(result.meta.settings, {
    serverLogLevel: 'info',
    serverLogTimestamp: false,
    serverLogFile: '',
    futureSetting: 'kept',
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

test('Trojan buildServerInbound preserves custom self-signed certificate paths', () => {
  const entry = {
    port: 443,
    password: 'test',
    tlsMode: 'self-signed',
    domain: 'example.com',
    certificatePath: '/srv/tls/server.crt',
    keyPath: '/srv/tls/server.key',
  }
  const inbound = PROTOCOL_REGISTRY.trojan.buildServerInbound(entry)

  assert.deepEqual(inbound.tls, {
    enabled: true,
    server_name: 'example.com',
    certificate_path: '/srv/tls/server.crt',
    key_path: '/srv/tls/server.key',
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
