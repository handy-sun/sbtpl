import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

import {
  buildAcmeProvider,
  buildServerInboundTag,
  buildServerLog,
  getLocalIpFromInterfaces,
  getTrojanCertPaths,
  parseDnsOptions,
  normalizeMeta,
  resolveServerIpInput,
  validateProtocolTag,
  validateTrojanEntry,
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

test('server generation emits top-level ACME certificate providers for sing-box 1.14', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sbtpl-server-acme-test-'))
  const metaPath = path.join(dir, 'meta.json')
  const outputDir = path.join(dir, 'output')
  t.after(() => rm(dir, { recursive: true, force: true }))

  assert.equal(runServer('set', '--ip', '203.0.113.10', '--meta', metaPath).status, 0)
  assert.equal(runServer('add', 'trojan', '--domain', 'example.com', '--password', 'test', '--meta', metaPath).status, 0)
  assert.equal(runServer('gen', '-o', outputDir, '--meta', metaPath).status, 0)

  const serverConfig = JSON.parse(await readFile(path.join(outputDir, 'server-config.json'), 'utf8'))
  assert.deepEqual(serverConfig.certificate_providers, [{
    type: 'acme',
    tag: 'trojan-443-acme',
    domain: ['example.com'],
  }])
  assert.equal(serverConfig.inbounds[0].tls.certificate_provider, 'trojan-443-acme')

  const nixModule = await readFile(path.join(outputDir, 'sing-box-server.nix'), 'utf8')
  assert.match(nixModule, /certificate_provider = "trojan-443-acme";/)
  assert.match(nixModule, /certificate_providers = \[/)
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

test('Trojan buildServerInbound with acme mode uses a certificate provider', () => {
  const entry = { port: 443, password: 'test', tlsMode: 'acme', domain: 'example.com' }
  const inbound = PROTOCOL_REGISTRY.trojan.buildServerInbound(entry)
  assert.equal(inbound.type, 'trojan')
  assert.deepEqual(inbound.tls, {
    enabled: true,
    server_name: 'example.com',
    certificate_provider: {
      type: 'acme',
      domain: ['example.com'],
    },
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

test('getTrojanCertPaths derives nixos acme paths from the domain', () => {
  assert.deepEqual(getTrojanCertPaths({ domain: 'example.com', tlsMode: 'file' }), {
    certPath: '/var/lib/acme/example.com/fullchain.pem',
    keyPath: '/var/lib/acme/example.com/key.pem',
  })
})

test('getTrojanCertPaths prefers explicit paths and falls back to empty', () => {
  assert.deepEqual(
    getTrojanCertPaths({ domain: 'example.com', certPath: '/srv/full.pem', keyPath: '/srv/key.pem' }),
    { certPath: '/srv/full.pem', keyPath: '/srv/key.pem' },
  )
  assert.deepEqual(getTrojanCertPaths({ tlsMode: 'file' }), { certPath: '', keyPath: '' })
})

test('validateTrojanEntry accepts the supported TLS modes', () => {
  assert.equal(validateTrojanEntry({ tlsMode: 'acme', domain: 'example.com' }), null)
  assert.equal(validateTrojanEntry({ tlsMode: 'self-signed' }), null)
  assert.equal(validateTrojanEntry({ tlsMode: 'file', domain: 'example.com' }), null)
  assert.equal(validateTrojanEntry({ tlsMode: 'file', certPath: '/a.pem', keyPath: '/b.key' }), null)

  assert.match(validateTrojanEntry({ tlsMode: 'bogus' }), /must be one of/i)
  assert.match(validateTrojanEntry({ tlsMode: 'acme' }), /domain is required/i)
  assert.match(validateTrojanEntry({ tlsMode: 'file' }), /domain or cert-path is required/i)
})

test('Trojan buildServerInbound with file mode points at the external certificate', () => {
  const inbound = PROTOCOL_REGISTRY.trojan.buildServerInbound({
    tag: 'edge-trojan', port: 443, password: 'test', tlsMode: 'file', domain: 'example.com',
  })
  assert.deepEqual(inbound.tls, {
    enabled: true,
    server_name: 'example.com',
    certificate_path: '/var/lib/acme/example.com/fullchain.pem',
    key_path: '/var/lib/acme/example.com/key.pem',
  })
})

test('Trojan file mode keeps client certificate verification enabled', () => {
  const bean = PROTOCOL_REGISTRY.trojan.metaToBean(
    { tag: 'edge-trojan', port: 443, password: 'test', tlsMode: 'file', domain: 'example.com' },
    '203.0.113.10',
  )
  assert.equal(bean.allowInsecure, false)
})

test('server add honours --tls-mode and emits file-mode certificates', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sbtpl-server-file-test-'))
  const metaPath = path.join(dir, 'meta.json')
  const outputDir = path.join(dir, 'output')
  t.after(() => rm(dir, { recursive: true, force: true }))

  assert.equal(runServer('set', '--ip', '203.0.113.10', '--meta', metaPath).status, 0)
  const added = runServer('add', 'trojan', '--tls-mode', 'file', '--domain', 'example.com', '--password', 'test', '--meta', metaPath)
  assert.equal(added.status, 0, added.stderr)
  assert.equal(JSON.parse(await readFile(metaPath, 'utf8')).protocols[0].tlsMode, 'file')

  assert.equal(runServer('gen', '-o', outputDir, '--meta', metaPath).status, 0)

  const serverConfig = JSON.parse(await readFile(path.join(outputDir, 'server-config.json'), 'utf8'))
  assert.equal(serverConfig.certificate_providers, undefined)
  assert.deepEqual(serverConfig.inbounds[0].tls, {
    enabled: true,
    server_name: 'example.com',
    certificate_path: '/var/lib/acme/example.com/fullchain.pem',
    key_path: '/var/lib/acme/example.com/key.pem',
  })

  const clientConfig = JSON.parse(await readFile(path.join(outputDir, 'client-config.json'), 'utf8'))
  const outbound = clientConfig.outbounds.find(item => item.tag === 'trojan-443')
  assert.equal(outbound.tls.insecure, false)

  const nixModule = await readFile(path.join(outputDir, 'sing-box-server.nix'), 'utf8')
  assert.match(nixModule, /certificate_path = "\/var\/lib\/acme\/example.com\/fullchain.pem";/)
  assert.doesNotMatch(nixModule, /certificate_providers/)
})

test('server add keeps the self-signed tls mode from the command line', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sbtpl-server-selfsigned-test-'))
  const metaPath = path.join(dir, 'meta.json')
  t.after(() => rm(dir, { recursive: true, force: true }))

  assert.equal(runServer('set', '--ip', '203.0.113.10', '--meta', metaPath).status, 0)
  const added = runServer('add', 'trojan', '--tls-mode', 'self-signed', '--domain', 'example.com', '--meta', metaPath)
  assert.equal(added.status, 0, added.stderr)
  assert.equal(JSON.parse(await readFile(metaPath, 'utf8')).protocols[0].tlsMode, 'self-signed')
})

test('server add rejects file mode without a domain or certificate path', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sbtpl-server-file-invalid-'))
  const metaPath = path.join(dir, 'meta.json')
  t.after(() => rm(dir, { recursive: true, force: true }))

  assert.equal(runServer('set', '--ip', '203.0.113.10', '--meta', metaPath).status, 0)
  const added = runServer('add', 'trojan', '--tls-mode', 'file', '--password', 'test', '--meta', metaPath)
  assert.notEqual(added.status, 0)
  assert.match(added.stdout + added.stderr, /domain or cert-path is required/i)
})

test('buildAcmeProvider defaults to the SNI domain without a DNS challenge', () => {
  assert.deepEqual(
    buildAcmeProvider({ tag: 'trojan-443', domain: 'example.com', tlsMode: 'acme' }),
    { type: 'acme', tag: 'trojan-443-acme', domain: ['example.com'] },
  )
})

test('buildAcmeProvider emits dns01_challenge with wildcard domains', () => {
  const provider = buildAcmeProvider({
    tag: 'trojan-443',
    domain: 'vpn.647792.xyz',
    tlsMode: 'acme',
    acmeDomains: '*.647792.xyz, 647792.xyz',
    acmeEmail: 'me@example.com',
    acmeCa: 'zerossl',
    dnsProvider: 'cloudflare',
    dnsOptions: { api_token: '@/run/secrets/cf', zone_token: 'zone' },
  })

  assert.deepEqual(provider, {
    type: 'acme',
    tag: 'trojan-443-acme',
    domain: ['*.647792.xyz', '647792.xyz'],
    email: 'me@example.com',
    provider: 'zerossl',
    dns01_challenge: {
      provider: 'cloudflare',
      api_token: '@/run/secrets/cf',
      zone_token: 'zone',
    },
  })
})

test('parseDnsOptions accepts key=value lists and objects', () => {
  assert.deepEqual(parseDnsOptions('api_token=abc,zone_token=x=y'), {
    api_token: 'abc',
    zone_token: 'x=y',
  })
  assert.deepEqual(parseDnsOptions(['access_key_id=a', 'access_key_secret=b']), {
    access_key_id: 'a',
    access_key_secret: 'b',
  })
  assert.deepEqual(parseDnsOptions({ api_token: 'abc' }), { api_token: 'abc' })
  assert.throws(() => parseDnsOptions('broken'), /key=value/i)
})

test('validateTrojanEntry requires DNS-01 for wildcards and known providers', () => {
  assert.equal(validateTrojanEntry({ tlsMode: 'acme', domain: 'vpn.example.com' }), null)
  assert.equal(
    validateTrojanEntry({
      tlsMode: 'acme', domain: 'vpn.example.com', acmeDomains: '*.example.com',
      dnsProvider: 'cloudflare', dnsOptions: { api_token: 'x' },
    }),
    null,
  )

  assert.match(
    validateTrojanEntry({ tlsMode: 'acme', domain: 'vpn.example.com', acmeDomains: '*.example.com' }),
    /wildcard domain requires dns-provider/i,
  )
  assert.match(
    validateTrojanEntry({ tlsMode: 'acme', domain: 'vpn.example.com', dnsProvider: 'route53', dnsOptions: { a: 'b' } }),
    /dns-provider must be one of/i,
  )
  assert.match(
    validateTrojanEntry({ tlsMode: 'acme', domain: 'vpn.example.com', dnsProvider: 'cloudflare' }),
    /dns-option is required/i,
  )
})

test('server generation resolves @file DNS options into JSON and keeps _secret in Nix', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sbtpl-server-dns01-test-'))
  const metaPath = path.join(dir, 'meta.json')
  const outputDir = path.join(dir, 'output')
  const tokenPath = path.join(dir, 'cf-token')
  t.after(() => rm(dir, { recursive: true, force: true }))
  await writeFile(tokenPath, 'token-value\n')

  assert.equal(runServer('set', '--ip', '203.0.113.10', '--meta', metaPath).status, 0)
  const added = runServer(
    'add', 'trojan',
    '--domain', 'vpn.647792.xyz',
    '--acme-domain', '*.647792.xyz,647792.xyz',
    '--dns-provider', 'cloudflare',
    '--dns-option', `api_token=@${tokenPath}`,
    '--password', 'test',
    '--meta', metaPath,
  )
  assert.equal(added.status, 0, added.stderr)

  assert.equal(runServer('gen', '-o', outputDir, '--meta', metaPath).status, 0)

  const serverConfig = JSON.parse(await readFile(path.join(outputDir, 'server-config.json'), 'utf8'))
  assert.deepEqual(serverConfig.certificate_providers, [{
    type: 'acme',
    tag: 'trojan-443-acme',
    domain: ['*.647792.xyz', '647792.xyz'],
    dns01_challenge: { provider: 'cloudflare', api_token: 'token-value' },
  }])

  const nixModule = await readFile(path.join(outputDir, 'sing-box-server.nix'), 'utf8')
  assert.match(nixModule, /dns01_challenge = \{/)
  assert.match(nixModule, new RegExp(`api_token = \\{ _secret = "${tokenPath}"; \\};`))
  assert.doesNotMatch(nixModule, /token-value/)
})
