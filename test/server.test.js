import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs, {
  chmod, link, lstat, mkdtemp, readFile, readdir, readlink, rename, rm, stat, symlink, writeFile,
} from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

import {
  buildNixServerModule,
  buildSelfSignedTlsGuidance,
  buildServerInboundTag,
  buildServerLog,
  getLocalIpFromInterfaces,
  importServerConfig,
  normalizeMeta,
  resolveServerIpInput,
  serverImport,
  PROTOCOL_REGISTRY,
} from '../node/server.js'

const serverScript = path.resolve('node/server.js')
const shadowsocks2022Password = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='

async function withTempDir(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sbtpl-server-test-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  return dir
}

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

test('buildNixServerModule preserves an imported server log level', () => {
  const { meta } = importServerConfig({
    log: { level: 'warn', timestamp: true },
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: '11111111-2222-3333-4444-555555555555' }],
    }],
  }, {})
  const inbounds = meta.protocols.map(entry => PROTOCOL_REGISTRY[entry.type].buildServerInbound(entry))

  const nixModule = buildNixServerModule(inbounds, buildServerLog(meta.settings))

  assert.match(nixModule, /level = "warn";/)
  assert.match(nixModule, /timestamp = true;/)
})

test('buildNixServerModule escapes imported strings as literal Nix values', () => {
  const malicious = 'quote" slash\\ payload ${builtins.abort "pwn"}'
  const { meta } = importServerConfig({
    log: {
      level: 'warn',
      timestamp: true,
      output: `/var/log/${malicious}`,
    },
    inbounds: [
      {
        type: 'vmess',
        listen_port: 20086,
        users: [{ uuid: `vmess-${malicious}` }],
      },
      {
        type: 'trojan',
        listen_port: 443,
        users: [{ password: `trojan-${malicious}` }],
        tls: {
          enabled: true,
          server_name: `server-${malicious}`,
          certificate_path: `/srv/${malicious}.crt`,
          key_path: `/srv/${malicious}.key`,
        },
      },
      {
        type: 'shadowsocks',
        listen_port: 20085,
        method: 'aes-256-gcm',
        password: `shadowsocks-${malicious}`,
      },
    ],
  }, {})
  const inbounds = meta.protocols.map(entry => PROTOCOL_REGISTRY[entry.type].buildServerInbound(entry))
  inbounds[0].tag = `tag-${malicious}`
  inbounds.push(PROTOCOL_REGISTRY.trojan.buildServerInbound({
    port: 8443,
    password: `acme-password-${malicious}`,
    tlsMode: 'acme',
    domain: `acme-${malicious}`,
  }))

  const nixModule = buildNixServerModule(inbounds, buildServerLog(meta.settings))
  const nixLiteral = value => JSON.stringify(value).replaceAll('${', '\\${')
  const expectedAssignments = [
    `tag = ${nixLiteral(`tag-${malicious}`)};`,
    `uuid = ${nixLiteral(`vmess-${malicious}`)};`,
    `password = ${nixLiteral(`trojan-${malicious}`)};`,
    `server_name = ${nixLiteral(`server-${malicious}`)};`,
    `certificate_path = ${nixLiteral(`/srv/${malicious}.crt`)};`,
    `key_path = ${nixLiteral(`/srv/${malicious}.key`)};`,
    `method = ${nixLiteral('aes-256-gcm')};`,
    `password = ${nixLiteral(`shadowsocks-${malicious}`)};`,
    `password = ${nixLiteral(`acme-password-${malicious}`)};`,
    `server_name = ${nixLiteral(`acme-${malicious}`)};`,
    `domain = [ ${nixLiteral(`acme-${malicious}`)} ];`,
    `output = ${nixLiteral(`/var/log/${malicious}`)};`,
  ]

  for (const assignment of expectedAssignments) {
    assert.ok(nixModule.includes(assignment), `missing escaped Nix assignment: ${assignment}`)
  }
  assert.doesNotMatch(nixModule, /(?<!\\)\$\{builtins\.abort/)

  const nixVersion = spawnSync('nix-instantiate', ['--version'], { encoding: 'utf8' })
  if (nixVersion.error?.code !== 'ENOENT') {
    assert.equal(nixVersion.status, 0, nixVersion.stderr)
    const parsed = spawnSync('nix-instantiate', ['--parse', '--expr', nixModule], { encoding: 'utf8' })
    assert.equal(parsed.status, 0, parsed.stderr)
  }
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
        password: shadowsocks2022Password,
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
      password: shadowsocks2022Password,
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

test('importServerConfig rejects control characters in imported strings without exposing values', () => {
  const cases = [
    {
      config: {
        inbounds: [{
          type: 'vmess',
          listen_port: 20086,
          users: [{ uuid: 'vmess-credential\u001b[31m\nFORGED' }],
        }],
      },
      field: /inbound 0.*users\[0\]\.uuid/i,
      secret: /vmess-credential|FORGED/,
    },
    {
      config: {
        inbounds: [{
          type: 'trojan',
          listen_port: 443,
          users: [{ password: 'safe-password' }],
          tls: {
            enabled: true,
            server_name: 'domain-secret\u0085FORGED',
            certificate_path: '/srv/tls/server.crt',
            key_path: '/srv/tls/server.key',
          },
        }],
      },
      field: /inbound 0.*tls\.server_name/i,
      secret: /domain-secret|FORGED/,
    },
    {
      config: {
        inbounds: [{
          type: 'shadowsocks',
          listen_port: 20085,
          method: 'method-secret\u007fFORGED',
          password: 'safe-password',
        }],
      },
      field: /inbound 0.*method/i,
      secret: /method-secret|FORGED/,
    },
    {
      config: {
        inbounds: [{
          type: 'trojan',
          listen_port: 443,
          users: [{ password: 'safe-password' }],
          tls: {
            enabled: true,
            acme: { domain: ['acme-secret\u001b[31mFORGED'] },
          },
        }],
      },
      field: /inbound 0.*tls\.acme\.domain\[0\]/i,
      secret: /acme-secret|FORGED/,
    },
    {
      config: {
        log: { output: '/tmp/log-secret\nFORGED.log' },
        inbounds: [{
          type: 'vmess',
          listen_port: 20086,
          users: [{ uuid: 'safe-uuid' }],
        }],
      },
      field: /log\.output/i,
      secret: /log-secret|FORGED/,
    },
  ]

  for (const { config, field, secret } of cases) {
    assert.throws(() => importServerConfig(config, {}), (error) => {
      assert.match(error.message, field)
      assert.match(error.message, /control character/i)
      assert.doesNotMatch(error.message, secret)
      assert.doesNotMatch(error.message, /[\u0000-\u001f\u007f-\u009f]/u)
      return true
    })
  }
})

test('importServerConfig allows normal Unicode in imported strings', () => {
  const result = importServerConfig({
    log: {
      level: 'warn',
      output: '/日志/服务.log',
    },
    inbounds: [{
      type: 'shadowsocks',
      listen_port: 20085,
      method: 'aes-256-gcm',
      password: '安全密码',
    }],
  }, {})

  assert.equal(result.meta.protocols[0].method, 'aes-256-gcm')
  assert.equal(result.meta.protocols[0].password, '安全密码')
  assert.equal(result.meta.settings.serverLogLevel, 'warn')
  assert.equal(result.meta.settings.serverLogFile, '/日志/服务.log')
})

test('importServerConfig rejects unsupported log levels and Shadowsocks methods', () => {
  assert.throws(() => importServerConfig({
    log: { level: '警告' },
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: 'safe-uuid' }],
    }],
  }, {}), /log\.level.*one of/i)

  assert.throws(() => importServerConfig({
    inbounds: [{
      type: 'shadowsocks',
      listen_port: 20085,
      method: 'made-up-method',
      password: 'safe-password',
    }],
  }, {}), /inbound 0 method.*unsupported/i)
})

test('importServerConfig validates Shadowsocks 2022 password key lengths', () => {
  assert.throws(() => importServerConfig({
    inbounds: [{
      type: 'shadowsocks',
      listen_port: 20085,
      method: '2022-blake3-aes-256-gcm',
      password: 'c2hvcnQ=',
    }],
  }, {}), /inbound 0 password.*32-byte base64 key/i)
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

test('importServerConfig rejects non-object inbound entries even when a valid inbound follows', () => {
  const invalidInbounds = [
    null,
    42,
    'inbound-secret-must-not-leak',
    ['nested-secret-must-not-leak'],
  ]

  for (const invalidInbound of invalidInbounds) {
    assert.throws(() => importServerConfig({
      inbounds: [
        invalidInbound,
        {
          type: 'vmess',
          listen_port: 20086,
          users: [{ uuid: 'safe-uuid' }],
        },
      ],
    }, {}), (error) => {
      assert.match(error.message, /inbound 0.*object/i)
      assert.doesNotMatch(error.message, /secret-must-not-leak/)
      return true
    })
  }
})

test('importServerConfig rejects control characters in unsupported inbound types without exposing values', () => {
  assert.throws(() => importServerConfig({
    inbounds: [
      { type: 'http\u0085FORGED' },
      {
        type: 'vmess',
        listen_port: 20086,
        users: [{ uuid: 'safe-uuid' }],
      },
    ],
  }, {}), (error) => {
    assert.match(error.message, /inbound 0.*type.*control character/i)
    assert.doesNotMatch(error.message, /FORGED|\u0085/)
    return true
  })
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
        acme: { domain: ['first.example'] },
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

test('importServerConfig rejects ACME inbounds with multiple domains', () => {
  assert.throws(() => importServerConfig({
    inbounds: [{
      type: 'trojan',
      listen_port: 443,
      users: [{ password: 'trojan-secret' }],
      tls: {
        enabled: true,
        acme: { domain: ['first.example', 'second.example'] },
      },
    }],
  }, {}), /tls\.acme\.domain.*exactly one/i)
})

test('importServerConfig allows an empty Trojan server_name for self-signed TLS', () => {
  const result = importServerConfig({
    inbounds: [{
      type: 'trojan',
      listen_port: 443,
      users: [{ password: 'trojan-secret' }],
      tls: {
        enabled: true,
        server_name: '',
        certificate_path: '/srv/tls/server.crt',
        key_path: '/srv/tls/server.key',
      },
    }],
  }, {})

  assert.deepEqual(result.meta.protocols, [{
    type: 'trojan',
    port: 443,
    password: 'trojan-secret',
    tlsMode: 'self-signed',
    domain: '',
    certificatePath: '/srv/tls/server.crt',
    keyPath: '/srv/tls/server.key',
  }])
})

test('importServerConfig rejects non-string ACME domains without exposing credentials', () => {
  assert.throws(() => importServerConfig({
    inbounds: [{
      type: 'trojan',
      listen_port: 443,
      users: [{ password: 'trojan-secret-must-not-leak' }],
      tls: {
        enabled: true,
        acme: { domain: [42] },
      },
    }],
  }, {}), (error) => {
    assert.match(error.message, /inbound 0.*tls\.acme\.domain\[0\].*non-empty string/i)
    assert.doesNotMatch(error.message, /trojan-secret-must-not-leak/)
    return true
  })
})

test('importServerConfig rejects invalid non-empty Trojan server_name values', () => {
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

test('server -i imports supported inbounds, warns for skipped ones, and preserves unrelated metadata', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'server-config.json')
  const metaPath = path.join(dir, 'meta.json')
  await writeFile(metaPath, JSON.stringify({
    ip: '203.0.113.10',
    protocols: [{ type: 'vmess', port: 1, uuid: 'old-uuid' }],
    settings: {
      serverLogLevel: 'error',
      serverLogTimestamp: false,
      serverLogFile: '/tmp/old.log',
      futureSetting: 'kept',
    },
    extra: 'kept',
  }))
  await chmod(metaPath, 0o640)
  await writeFile(importPath, JSON.stringify({
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
      { type: 'http', listen_port: 8080 },
    ],
  }))

  const result = runServer('-i', importPath, '--meta', metaPath)

  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /imported 1 supported inbound/i)
  assert.match(result.stdout + result.stderr, /inbound 1.*unsupported.*http/i)
  assert.match(result.stdout, /skipped 1 unsupported inbound/i)
  const saved = JSON.parse(await readFile(metaPath, 'utf8'))
  assert.deepEqual(saved.protocols, [{
    type: 'vmess',
    port: 20086,
    uuid: '11111111-2222-3333-4444-555555555555',
  }])
  assert.equal(saved.ip, '203.0.113.10')
  assert.equal(saved.extra, 'kept')
  assert.deepEqual(saved.settings, {
    serverLogLevel: 'warn',
    serverLogTimestamp: true,
    serverLogFile: '/var/log/sing-box/server.log',
    futureSetting: 'kept',
  })
  assert.equal((await stat(metaPath)).mode & 0o777, 0o640)
})

test('server --import accepts the long flag and hints when server IP is empty', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'server-config.json')
  const metaPath = path.join(dir, 'meta.json')
  await writeFile(importPath, JSON.stringify({
    inbounds: [{
      type: 'shadowsocks',
      listen_port: 20085,
      method: '2022-blake3-aes-256-gcm',
      password: shadowsocks2022Password,
    }],
  }))

  const result = runServer('--import', importPath, '--meta', metaPath)

  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /imported 1 supported inbound/i)
  assert.match(result.stdout, /sbtpl server set --ip <addr>/i)
  const saved = JSON.parse(await readFile(metaPath, 'utf8'))
  assert.deepEqual(saved.protocols, [{
    type: 'ss',
    port: 20085,
    method: '2022-blake3-aes-256-gcm',
    password: shadowsocks2022Password,
  }])
  assert.equal((await stat(metaPath)).mode & 0o777, 0o600)
})

test('server import read and JSON failures preserve metadata bytes', async (t) => {
  const dir = await withTempDir(t)
  const metaPath = path.join(dir, 'meta.json')
  const invalidJsonPath = path.join(dir, 'invalid.json')
  const originalMeta = Buffer.from('{"ip":"203.0.113.10","extra":"unchanged"}\n')
  await writeFile(metaPath, originalMeta)
  await writeFile(invalidJsonPath, '{"password":"credential-must-not-leak",')

  const cases = [
    {
      importPath: path.join(dir, 'missing.json'),
      message: /missing\.json/i,
    },
    {
      importPath: invalidJsonPath,
      message: /invalid JSON.*invalid\.json/i,
    },
  ]

  for (const { importPath, message } of cases) {
    const result = runServer('--import', importPath, '--meta', metaPath)
    const output = result.stdout + result.stderr

    assert.notEqual(result.status, 0)
    assert.match(output, message)
    assert.doesNotMatch(output, /credential-must-not-leak/)
    assert.doesNotMatch(output, /\n\s+at\s|node:internal|file:\/\//i)
    assert.deepEqual(await readFile(metaPath), originalMeta)
  }
})

test('server import does not replace malformed existing metadata', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'server-config.json')
  const metaPath = path.join(dir, 'meta.json')
  const originalMeta = Buffer.from('{"ip":"203.0.113.10",')
  await writeFile(metaPath, originalMeta)
  await writeFile(importPath, JSON.stringify({
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: 'credential-must-not-leak' }],
    }],
  }))

  const result = runServer('--import', importPath, '--meta', metaPath)
  const output = result.stdout + result.stderr

  assert.notEqual(result.status, 0)
  assert.match(output, /could not load metadata.*meta\.json/i)
  assert.doesNotMatch(output, /credential-must-not-leak/)
  assert.doesNotMatch(output, /\n\s+at\s|node:internal|file:\/\//i)
  assert.deepEqual(await readFile(metaPath), originalMeta)
})

test('server import validation failure is concise, hides credentials, and preserves metadata bytes', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'server-config.json')
  const metaPath = path.join(dir, 'meta.json')
  const originalMeta = Buffer.from('{"ip":"203.0.113.10", "extra":"byte-for-byte"}\n')
  await writeFile(metaPath, originalMeta)
  await writeFile(importPath, JSON.stringify({
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: { value: 'credential-must-not-leak' } }],
    }],
  }))

  const result = runServer('-i', importPath, '--meta', metaPath)

  assert.notEqual(result.status, 0)
  const output = result.stdout + result.stderr
  assert.match(output, /inbound 0.*uuid/i)
  assert.doesNotMatch(output, /credential-must-not-leak/)
  assert.doesNotMatch(output, /\n\s+at\s|node:internal|file:\/\//i)
  assert.deepEqual(await readFile(metaPath), originalMeta)
})

test('server import rejects control characters without terminal injection or metadata writes', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'server-config.json')
  const metaPath = path.join(dir, 'meta.json')
  const originalMeta = Buffer.from('{"ip":"203.0.113.10","protocols":[]}\n')
  const cases = [
    {
      config: {
        inbounds: [{
          type: 'vmess',
          listen_port: 20086,
          users: [{ uuid: 'vmess-credential\u001b[31m\nFORGED' }],
        }],
      },
      field: /users\[0\]\.uuid/i,
    },
    {
      config: {
        inbounds: [{
          type: 'trojan',
          listen_port: 443,
          users: [{ password: 'safe-password' }],
          tls: {
            enabled: true,
            server_name: 'domain-credential\u0085FORGED',
            certificate_path: '/srv/tls/server.crt',
            key_path: '/srv/tls/server.key',
          },
        }],
      },
      field: /tls\.server_name/i,
    },
    {
      config: {
        inbounds: [{
          type: 'shadowsocks',
          listen_port: 20085,
          method: 'method-credential\u007fFORGED',
          password: 'safe-password',
        }],
      },
      field: /method/i,
    },
  ]

  for (const { config, field } of cases) {
    await writeFile(metaPath, originalMeta)
    await writeFile(importPath, JSON.stringify(config))

    const result = runServer('--import', importPath, '--meta', metaPath)
    const output = result.stdout + result.stderr

    assert.notEqual(result.status, 0)
    assert.match(output, field)
    assert.match(output, /control character/i)
    assert.doesNotMatch(output, /\u001b|FORGED|credential/i)
    assert.doesNotMatch(output, /\n\s+at\s|node:internal|file:\/\//i)
    assert.deepEqual(await readFile(metaPath), originalMeta)
  }
})

test('server import rejects controls in unsupported inbound types without writing metadata', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'server-config.json')
  const metaPath = path.join(dir, 'meta.json')
  const originalMeta = Buffer.from('{"ip":"203.0.113.10","protocols":[]}\n')
  await writeFile(metaPath, originalMeta)
  await writeFile(importPath, JSON.stringify({
    inbounds: [
      { type: 'http\u0085FORGED' },
      {
        type: 'vmess',
        listen_port: 20086,
        users: [{ uuid: 'safe-uuid' }],
      },
    ],
  }))

  const result = runServer('--import', importPath, '--meta', metaPath)
  const output = result.stdout + result.stderr

  assert.notEqual(result.status, 0)
  assert.match(output, /inbound 0.*type.*control character/i)
  assert.doesNotMatch(output, /FORGED|\u0085/)
  assert.doesNotMatch(output, /\n\s+at\s|node:internal|file:\/\//i)
  assert.deepEqual(await readFile(metaPath), originalMeta)
})

test('server rejects combining a subcommand with --import without writing metadata', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'server-config.json')
  const metaPath = path.join(dir, 'meta.json')
  const originalMeta = Buffer.from('{"ip":"203.0.113.10","protocols":[]}\n')
  await writeFile(metaPath, originalMeta)
  await writeFile(importPath, JSON.stringify({
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: '11111111-2222-3333-4444-555555555555' }],
    }],
  }))

  for (const args of [
    ['list', '--import', importPath, '--meta', metaPath],
    ['--import', importPath, 'list', '--meta', metaPath],
  ]) {
    const result = runServer(...args)
    const output = result.stdout + result.stderr

    assert.notEqual(result.status, 0)
    assert.match(output, /cannot.*--import.*subcommand|--import.*cannot.*subcommand/i)
    assert.doesNotMatch(output, /\n\s+at\s|node:internal|file:\/\//i)
    assert.deepEqual(await readFile(metaPath), originalMeta)
  }
})

test('server import rejects identical source and metadata paths without changing the source', async (t) => {
  const dir = await withTempDir(t)
  const configPath = path.join(dir, 'same.json')
  const original = Buffer.from(JSON.stringify({
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: '11111111-2222-3333-4444-555555555555' }],
    }],
  }))
  await writeFile(configPath, original)

  const result = runServer('--import', configPath, '--meta', configPath)

  assert.notEqual(result.status, 0)
  assert.match(result.stdout + result.stderr, /import path.*metadata path.*different/i)
  assert.deepEqual(await readFile(configPath), original)
})

test('server import rejects symlink aliases without changing the source', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'source.json')
  const metaPath = path.join(dir, 'meta-link.json')
  const original = Buffer.from(JSON.stringify({
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: '11111111-2222-3333-4444-555555555555' }],
    }],
  }))
  await writeFile(importPath, original)
  await symlink(importPath, metaPath)

  const result = runServer('--import', importPath, '--meta', metaPath)

  assert.notEqual(result.status, 0)
  assert.match(result.stdout + result.stderr, /same file|alias/i)
  assert.deepEqual(await readFile(importPath), original)
  assert.equal((await lstat(metaPath)).isSymbolicLink(), true)
})

test('server import updates an existing metadata symlink target without replacing the link', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'source.json')
  const targetPath = path.join(dir, 'meta-target.json')
  const metaPath = path.join(dir, 'meta-link.json')
  await writeFile(importPath, JSON.stringify({
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: '11111111-2222-3333-4444-555555555555' }],
    }],
  }))
  await writeFile(targetPath, JSON.stringify({
    ip: '203.0.113.10',
    protocols: [{ type: 'vmess', port: 1, uuid: 'old-uuid' }],
  }))
  await chmod(targetPath, 0o640)
  await symlink(targetPath, metaPath)

  const result = runServer('--import', importPath, '--meta', metaPath)

  assert.equal(result.status, 0, result.stderr)
  assert.equal((await lstat(metaPath)).isSymbolicLink(), true)
  assert.equal(await readlink(metaPath), targetPath)
  const saved = JSON.parse(await readFile(targetPath, 'utf8'))
  assert.equal(saved.ip, '203.0.113.10')
  assert.deepEqual(saved.protocols, [{
    type: 'vmess',
    port: 20086,
    uuid: '11111111-2222-3333-4444-555555555555',
  }])
  assert.equal((await stat(targetPath)).mode & 0o777, 0o640)
  assert.deepEqual((await readdir(dir)).sort(), [
    'meta-link.json',
    'meta-target.json',
    'source.json',
  ])
})

test('server import leaves a dangling metadata symlink unchanged without temp files', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'source.json')
  const missingTarget = path.join(dir, 'missing-meta.json')
  const metaPath = path.join(dir, 'meta-link.json')
  await writeFile(importPath, JSON.stringify({
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: '11111111-2222-3333-4444-555555555555' }],
    }],
  }))
  await symlink(missingTarget, metaPath)

  const result = runServer('--import', importPath, '--meta', metaPath)

  assert.notEqual(result.status, 0)
  assert.match(result.stdout + result.stderr, /metadata symlink.*ENOENT/i)
  assert.equal((await lstat(metaPath)).isSymbolicLink(), true)
  assert.equal(await readlink(metaPath), missingTarget)
  assert.deepEqual((await readdir(dir)).sort(), ['meta-link.json', 'source.json'])
})

test('server import rejects non-object metadata roots without rewriting them', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'source.json')
  const metaPath = path.join(dir, 'meta.json')
  await writeFile(importPath, JSON.stringify({
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: '11111111-2222-3333-4444-555555555555' }],
    }],
  }))

  for (const rawMeta of ['[]', 'null', '42', '"primitive"']) {
    const original = Buffer.from(rawMeta)
    await writeFile(metaPath, original)

    const result = runServer('--import', importPath, '--meta', metaPath)

    assert.notEqual(result.status, 0)
    assert.match(result.stdout + result.stderr, /metadata root.*object/i)
    assert.deepEqual(await readFile(metaPath), original)
  }
})

test('server import rejects metadata hardlinks without changing either link', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'source.json')
  const metaPath = path.join(dir, 'meta.json')
  const hardlinkPath = path.join(dir, 'meta-backup.json')
  const originalMeta = Buffer.from('{"ip":"203.0.113.10","protocols":[]}\n')
  await writeFile(metaPath, originalMeta)
  await link(metaPath, hardlinkPath)
  await writeFile(importPath, JSON.stringify({
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: 'safe-uuid' }],
    }],
  }))

  const result = runServer('--import', importPath, '--meta', metaPath)
  const output = result.stdout + result.stderr

  assert.notEqual(result.status, 0)
  assert.match(output, /hardlink|multiple links|nlink/i)
  assert.deepEqual(await readFile(metaPath), originalMeta)
  assert.deepEqual(await readFile(hardlinkPath), originalMeta)
  assert.deepEqual((await readdir(dir)).sort(), ['meta-backup.json', 'meta.json', 'source.json'])
})

test('server import aborts if the metadata target gains a hardlink before rename', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'source.json')
  const metaPath = path.join(dir, 'meta.json')
  const hardlinkPath = path.join(dir, 'meta-backup.json')
  const originalMeta = Buffer.from('{"ip":"203.0.113.10","protocols":[]}\n')
  const originalImport = Buffer.from(JSON.stringify({
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: 'safe-uuid' }],
    }],
  }))
  await writeFile(metaPath, originalMeta)
  await writeFile(importPath, originalImport)

  const originalOpen = fs.open.bind(fs)
  let linked = false
  t.mock.method(fs, 'open', async (filePath, ...args) => {
    const handle = await originalOpen(filePath, ...args)
    if (filePath === metaPath && args[0] === 'r') {
      const originalHandleReadFile = handle.readFile.bind(handle)
      handle.readFile = async (...readArgs) => {
        const contents = await originalHandleReadFile(...readArgs)
        if (!linked) {
          linked = true
          await link(metaPath, hardlinkPath)
        }
        return contents
      }
    }
    return handle
  })

  await assert.rejects(
    serverImport(importPath, metaPath),
    /hardlink|multiple links|nlink/i,
  )
  assert.deepEqual(await readFile(importPath), originalImport)
  assert.deepEqual(await readFile(metaPath), originalMeta)
  assert.deepEqual(await readFile(hardlinkPath), originalMeta)
  assert.deepEqual((await readdir(dir)).sort(), ['meta-backup.json', 'meta.json', 'source.json'])
})

test('server import freezes the metadata symlink target before opening metadata', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'source.json')
  const targetPath = path.join(dir, 'meta-target.json')
  const metaPath = path.join(dir, 'meta-link.json')
  const originalImport = Buffer.from(JSON.stringify({
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: 'safe-uuid' }],
    }],
  }))
  await writeFile(importPath, originalImport)
  await writeFile(targetPath, JSON.stringify({
    ip: '203.0.113.10',
    protocols: [],
  }))
  await symlink(targetPath, metaPath)

  const originalOpen = fs.open.bind(fs)
  let swapped = false
  t.mock.method(fs, 'open', async (filePath, ...args) => {
    if (!swapped && args[0] === 'r' && (filePath === metaPath || filePath === targetPath)) {
      swapped = true
      await rm(metaPath)
      await symlink(importPath, metaPath)
    }
    return originalOpen(filePath, ...args)
  })

  await serverImport(importPath, metaPath)

  assert.deepEqual(await readFile(importPath), originalImport)
  assert.equal((await lstat(metaPath)).isSymbolicLink(), true)
  assert.equal(await readlink(metaPath), importPath)
  const saved = JSON.parse(await readFile(targetPath, 'utf8'))
  assert.equal(saved.ip, '203.0.113.10')
  assert.deepEqual(saved.protocols, [{
    type: 'vmess',
    port: 20086,
    uuid: 'safe-uuid',
  }])
})

test('server import keeps writing the frozen target if the requested symlink changes after opening metadata', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'source.json')
  const targetPath = path.join(dir, 'meta-target.json')
  const metaPath = path.join(dir, 'meta-link.json')
  const originalImport = Buffer.from(JSON.stringify({
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: 'safe-uuid' }],
    }],
  }))
  await writeFile(importPath, originalImport)
  await writeFile(targetPath, JSON.stringify({
    ip: '203.0.113.10',
    protocols: [],
  }))
  await symlink(targetPath, metaPath)

  const originalOpen = fs.open.bind(fs)
  let swapped = false
  t.mock.method(fs, 'open', async (filePath, ...args) => {
    const handle = await originalOpen(filePath, ...args)
    if (args[0] === 'r' && (filePath === metaPath || filePath === targetPath)) {
      const originalHandleReadFile = handle.readFile.bind(handle)
      handle.readFile = async (...readArgs) => {
        const contents = await originalHandleReadFile(...readArgs)
        if (!swapped) {
          swapped = true
          await rm(metaPath)
          await symlink(importPath, metaPath)
        }
        return contents
      }
    }
    return handle
  })

  await serverImport(importPath, metaPath)

  assert.deepEqual(await readFile(importPath), originalImport)
  assert.equal((await lstat(metaPath)).isSymbolicLink(), true)
  assert.equal(await readlink(metaPath), importPath)
  const saved = JSON.parse(await readFile(targetPath, 'utf8'))
  assert.equal(saved.ip, '203.0.113.10')
  assert.deepEqual(saved.protocols, [{
    type: 'vmess',
    port: 20086,
    uuid: 'safe-uuid',
  }])
})

test('server import aborts if the frozen metadata target is replaced before rename', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'source.json')
  const metaPath = path.join(dir, 'meta.json')
  const backupPath = path.join(dir, 'meta-original.json')
  const originalMeta = Buffer.from('{"ip":"203.0.113.10","protocols":[]}\n')
  const originalImport = Buffer.from(JSON.stringify({
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: 'safe-uuid' }],
    }],
  }))
  await writeFile(metaPath, originalMeta)
  await writeFile(importPath, originalImport)

  const originalOpen = fs.open.bind(fs)
  let swapped = false
  t.mock.method(fs, 'open', async (filePath, ...args) => {
    const handle = await originalOpen(filePath, ...args)
    if (filePath === metaPath && args[0] === 'r') {
      const originalHandleReadFile = handle.readFile.bind(handle)
      handle.readFile = async (...readArgs) => {
        const contents = await originalHandleReadFile(...readArgs)
        if (!swapped) {
          swapped = true
          await rename(metaPath, backupPath)
          await symlink(backupPath, metaPath)
        }
        return contents
      }
    }
    return handle
  })

  await assert.rejects(
    serverImport(importPath, metaPath),
    /metadata target.*changed/i,
  )
  assert.deepEqual(await readFile(importPath), originalImport)
  assert.deepEqual(await readFile(backupPath), originalMeta)
  assert.equal((await lstat(metaPath)).isSymbolicLink(), true)
  assert.equal(await readlink(metaPath), backupPath)
  assert.deepEqual((await readdir(dir)).sort(), ['meta-original.json', 'meta.json', 'source.json'])
})

test('server import quotes control characters in path success and error diagnostics', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'source\n\u001b[31mFORGED.json')
  const metaPath = path.join(dir, 'meta\n\u001b[32mFORGED.json')
  await writeFile(importPath, JSON.stringify({
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: '11111111-2222-3333-4444-555555555555' }],
    }],
  }))

  const success = runServer('--import', importPath, '--meta', metaPath)
  const successOutput = success.stdout + success.stderr

  assert.equal(success.status, 0, successOutput)
  assert.ok(successOutput.includes(JSON.stringify(importPath)))
  assert.ok(successOutput.includes(JSON.stringify(metaPath)))
  assert.equal(successOutput.includes(importPath), false)
  assert.equal(successOutput.includes(metaPath), false)
  assert.doesNotMatch(successOutput, /\u001b/)

  const missingPath = path.join(dir, 'missing\n\u001b[33mFORGED.json')
  const failure = runServer('--import', missingPath, '--meta', metaPath)
  const failureOutput = failure.stdout + failure.stderr

  assert.notEqual(failure.status, 0)
  assert.ok(failureOutput.includes(JSON.stringify(missingPath)))
  assert.match(failureOutput, /ENOENT/)
  assert.equal(failureOutput.includes(missingPath), false)
  assert.doesNotMatch(failureOutput, /\u001b/)

  await writeFile(metaPath, '{')
  const metaFailure = runServer('--import', importPath, '--meta', metaPath)
  const metaFailureOutput = metaFailure.stdout + metaFailure.stderr

  assert.notEqual(metaFailure.status, 0)
  assert.ok(metaFailureOutput.includes(JSON.stringify(metaPath)))
  assert.equal(metaFailureOutput.includes(metaPath), false)
  assert.doesNotMatch(metaFailureOutput, /\u001b/)
})

test('self-signed TLS guidance quotes control characters in certificate paths', () => {
  const certificatePath = '/srv/tls/cert\n\u001b[31mFORGED.crt'
  const keyPath = '/srv/tls/key\n\u001b[32mFORGED.key'

  const guidance = buildSelfSignedTlsGuidance({
    port: 443,
    password: 'test',
    tlsMode: 'self-signed',
    certificatePath,
    keyPath,
  })

  assert.ok(guidance.includes(JSON.stringify(certificatePath)))
  assert.ok(guidance.includes(JSON.stringify(keyPath)))
  assert.equal(guidance.includes(certificatePath), false)
  assert.equal(guidance.includes(keyPath), false)
  assert.doesNotMatch(guidance, /\u001b\[(31|32)mFORGED/)
})

test('serverImport keeps existing metadata and cleans its temp file when a write fails', async (t) => {
  const dir = await withTempDir(t)
  const importPath = path.join(dir, 'source.json')
  const metaPath = path.join(dir, 'meta.json')
  const originalMeta = Buffer.from('{"ip":"203.0.113.10","protocols":[]}\n')
  await writeFile(metaPath, originalMeta)
  await writeFile(importPath, JSON.stringify({
    inbounds: [{
      type: 'vmess',
      listen_port: 20086,
      users: [{ uuid: '11111111-2222-3333-4444-555555555555' }],
    }],
  }))

  const originalOpen = fs.open.bind(fs)
  let openedPath
  let openedFlags
  t.mock.method(fs, 'open', async (...args) => {
    openedPath = args[0]
    openedFlags = args[1]
    const handle = await originalOpen(...args)
    const originalWriteFile = handle.writeFile.bind(handle)
    handle.writeFile = async (data, ...writeArgs) => {
      await originalWriteFile(String(data).slice(0, 16), ...writeArgs)
      const error = new Error('deterministic partial write failure')
      error.code = 'EFBIG'
      throw error
    }
    return handle
  })

  await assert.rejects(
    serverImport(importPath, metaPath),
    /could not save metadata.*EFBIG/i,
  )
  assert.equal(path.dirname(openedPath), dir)
  assert.equal(openedFlags, 'wx')
  assert.notEqual(openedPath, metaPath)
  assert.deepEqual(await readFile(metaPath), originalMeta)
  assert.deepEqual((await readdir(dir)).sort(), ['meta.json', 'source.json'])
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

test('self-signed TLS guidance reports the effective certificate paths', () => {
  const customGuidance = buildSelfSignedTlsGuidance({
    port: 443,
    password: 'test',
    tlsMode: 'self-signed',
    domain: 'example.com',
    certificatePath: '/srv/tls/server.crt',
    keyPath: '/srv/tls/server.key',
  })
  assert.match(customGuidance, /\/srv\/tls\/server\.crt/)
  assert.match(customGuidance, /\/srv\/tls\/server\.key/)
  assert.doesNotMatch(customGuidance, /\/etc\/sing-box\/tls\.(cer|key)/)

  const defaultGuidance = buildSelfSignedTlsGuidance({
    port: 443,
    password: 'test',
    tlsMode: 'self-signed',
    domain: 'example.com',
  })
  assert.match(defaultGuidance, /\/etc\/sing-box\/tls\.cer/)
  assert.match(defaultGuidance, /\/etc\/sing-box\/tls\.key/)
})

test('Trojan metaToBean sets allowInsecure for self-signed mode', () => {
  const entrySelfSigned = { port: 443, password: 'test', tlsMode: 'self-signed', domain: 'example.com' }
  const bean1 = PROTOCOL_REGISTRY.trojan.metaToBean(entrySelfSigned, '1.2.3.4')
  assert.equal(bean1.allowInsecure, true)

  const entryAcme = { port: 443, password: 'test', tlsMode: 'acme', domain: 'example.com' }
  const bean2 = PROTOCOL_REGISTRY.trojan.metaToBean(entryAcme, '1.2.3.4')
  assert.equal(bean2.allowInsecure, false)
})
