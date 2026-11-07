import { parseArgs } from 'node:util'
import { createInterface } from 'node:readline'
import path from 'node:path'
import os from 'node:os'
import fs from 'fs/promises'

import {
  VMessBean, TrojanBean, ShadowsocksBean,
  buildSingboxOutbound,
  generateUUID, generateRandomBase64,
  sbtplLog, sbtplErr, safeParseInt,
} from './base.js'

// --- 服务端配置管理 ---

const DEFAULT_META_PATH = path.join(os.homedir(), '.config/sbtpl/meta.json')
const DEFAULT_SERVER_SETTINGS = {
  serverLogTimestamp: false,
  serverLogFile: '',
}
const RESERVED_PROTOCOL_TAGS = new Set(['direct', 'proxy'])

export const TROJAN_TLS_MODES = ['acme', 'self-signed', 'file']
export const DNS01_PROVIDERS = ['cloudflare', 'alidns', 'acmedns']
const NIXOS_ACME_DIR = '/var/lib/acme'

// A "file" TLS mode entry points sing-box at certificates managed elsewhere,
// for example by the NixOS security.acme module.
export function getTrojanCertPaths(entry = {}) {
  const dir = entry.domain ? path.posix.join(NIXOS_ACME_DIR, entry.domain) : ''
  return {
    certPath: entry.certPath || (dir ? `${dir}/fullchain.pem` : ''),
    keyPath: entry.keyPath || (dir ? `${dir}/key.pem` : ''),
  }
}

export function splitDomains(value) {
  if (Array.isArray(value)) return value.flatMap(splitDomains)
  if (typeof value !== 'string') return []
  return value.split(',').map(item => item.trim()).filter(Boolean)
}

// acmeDomains defaults to the SNI domain; wildcards belong here, not in domain.
export function getAcmeDomains(entry = {}) {
  const domains = splitDomains(entry.acmeDomains)
  if (domains.length) return domains
  return entry.domain ? [entry.domain] : []
}

export function parseDnsOptions(input) {
  if (input && typeof input === 'object' && !Array.isArray(input)) return { ...input }
  const items = Array.isArray(input) ? input : String(input ?? '').split(/[,;]/)
  const options = {}
  for (const raw of items) {
    const item = String(raw).trim()
    if (!item) continue
    const separator = item.indexOf('=')
    if (separator <= 0) throw new Error(`dns option must be key=value, got ${JSON.stringify(item)}`)
    options[item.slice(0, separator).trim()] = item.slice(separator + 1).trim()
  }
  return options
}

function coerceDnsOptions(value) {
  try {
    return parseDnsOptions(value)
  } catch {
    return {}
  }
}

// Builds one top-level certificate provider. Option values written as "@/path"
// are secret files: they are inlined for JSON and kept as _secret in the Nix module.
export function buildAcmeProvider(entry = {}) {
  const provider = {
    type: 'acme',
    tag: `${getProtocolTag(entry)}-acme`,
    domain: getAcmeDomains(entry),
  }
  if (entry.acmeEmail) provider.email = entry.acmeEmail
  if (entry.acmeCa) provider.provider = entry.acmeCa
  if (entry.dnsProvider) {
    provider.dns01_challenge = { provider: entry.dnsProvider, ...coerceDnsOptions(entry.dnsOptions) }
  }
  return provider
}

export function validateTrojanEntry(entry = {}) {
  if (!TROJAN_TLS_MODES.includes(entry.tlsMode)) {
    return `tls-mode must be one of ${TROJAN_TLS_MODES.join(', ')}`
  }
  if (entry.tlsMode === 'acme') {
    const domains = getAcmeDomains(entry)
    if (!domains.length) return 'domain is required when tls-mode is acme'
    if (entry.dnsProvider && !DNS01_PROVIDERS.includes(entry.dnsProvider)) {
      return `dns-provider must be one of ${DNS01_PROVIDERS.join(', ')}`
    }
    if (domains.some(domain => domain.startsWith('*.')) && !entry.dnsProvider) {
      return 'wildcard domain requires dns-provider (DNS-01 challenge)'
    }
    if (entry.dnsProvider) {
      let options
      try {
        options = parseDnsOptions(entry.dnsOptions ?? '')
      } catch (error) {
        return error.message
      }
      if (!Object.keys(options).length) return 'dns-option is required when dns-provider is set'
    }
  }
  if (entry.tlsMode === 'file') {
    const { certPath, keyPath } = getTrojanCertPaths(entry)
    if (!certPath || !keyPath) return 'domain or cert-path is required when tls-mode is file'
  }
  return null
}

export function buildServerInboundTag(protocol, port) {
  return `${protocol}-${port}`
}

function getDefaultProtocolTag(entry) {
  if (typeof entry?.type !== 'string' || !Number.isInteger(entry.port)) return ''
  return buildServerInboundTag(entry.type, entry.port)
}

function getProtocolTag(entry) {
  if (typeof entry?.tag === 'string' && entry.tag.trim() !== '') return entry.tag.trim()
  return getDefaultProtocolTag(entry)
}

export function validateProtocolTag(tag, protocols = [], currentEntry) {
  if (typeof tag !== 'string' || tag.trim() === '') {
    throw new Error('tag must be a non-empty string')
  }
  const normalizedTag = tag.trim()
  if (/[\u0000-\u001f\u007f-\u009f]/u.test(normalizedTag)) {
    throw new Error('tag must not contain control characters')
  }
  if (RESERVED_PROTOCOL_TAGS.has(normalizedTag)) {
    throw new Error(`tag ${JSON.stringify(normalizedTag)} is reserved`)
  }
  if (protocols.some(entry => entry !== currentEntry && getProtocolTag(entry) === normalizedTag)) {
    throw new Error(`tag ${JSON.stringify(normalizedTag)} already exists`)
  }
  return normalizedTag
}

export const PROTOCOL_REGISTRY = {
  vmess: {
    label: 'VMess',
    defaultPort: 20086,
    fields: [
      { name: 'port', type: 'number', default: 20086, prompt: '端口' },
      { name: 'uuid', type: 'string', generate: () => generateUUID(), prompt: 'UUID' },
    ],
    buildServerInbound(entry) {
      return {
        type: 'vmess', tag: getProtocolTag(entry), listen: '::',
        listen_port: entry.port,
        users: [{ uuid: entry.uuid }],
      }
    },
    metaToBean(entry, ip) {
      const bean = new VMessBean()
      bean.serverAddress = ip
      bean.serverPort = entry.port
      bean.uuid = entry.uuid
      bean.encryption = 'auto'
      bean.name = getProtocolTag(entry) || this.label
      return bean
    },
    summary(entry) {
      return `port=${entry.port}  uuid=${entry.uuid}`
    },
    editableFields: ['port', 'uuid'],
  },
  trojan: {
    label: 'Trojan',
    defaultPort: 443,
    fields: [
      { name: 'port', type: 'number', default: 443, prompt: '端口' },
      { name: 'password', type: 'string', generate: () => generateRandomBase64(16), prompt: '密码' },
      { name: 'tlsMode', type: 'string', default: 'acme', prompt: 'TLS 模式 (acme/self-signed/file)' },
      { name: 'domain', type: 'string', prompt: '域名 (TLS server_name)' },
      {
        name: 'certPath', type: 'string', prompt: '证书路径 (留空=nixos acme 默认路径)',
        when: entry => entry.tlsMode === 'file',
      },
      {
        name: 'keyPath', type: 'string', prompt: '私钥路径 (留空=nixos acme 默认路径)',
        when: entry => entry.tlsMode === 'file',
      },
      {
        name: 'acmeGroup', type: 'string', default: 'acme', prompt: '证书所属组 (写入 extraGroups)',
        when: entry => entry.tlsMode === 'file',
      },
    ],
    buildServerInbound(entry, certificateProviderTag) {
      const tls = { enabled: true, server_name: entry.domain || '' }
      if (entry.tlsMode === 'self-signed') {
        tls.certificate_path = '/etc/sing-box/tls.cer'
        tls.key_path = '/etc/sing-box/tls.key'
      } else if (entry.tlsMode === 'file') {
        const { certPath, keyPath } = getTrojanCertPaths(entry)
        tls.certificate_path = certPath
        tls.key_path = keyPath
      } else {
        tls.certificate_provider = certificateProviderTag || {
          type: 'acme',
          domain: [entry.domain],
        }
      }
      return {
        type: 'trojan', tag: getProtocolTag(entry), listen: '::',
        listen_port: entry.port,
        users: [{ password: entry.password }],
        tls,
      }
    },
    metaToBean(entry, ip) {
      const bean = new TrojanBean()
      bean.serverAddress = ip
      bean.serverPort = entry.port
      bean.password = entry.password
      bean.sni = entry.domain || ip
      bean.security = 'tls'
      bean.allowInsecure = entry.tlsMode === 'self-signed'
      bean.name = getProtocolTag(entry) || this.label
      return bean
    },
    summary(entry) {
      const parts = [`port=${entry.port}`]
      if (entry.domain) parts.push(`domain=${entry.domain}`)
      parts.push(`tls=${entry.tlsMode || 'acme'}`)
      if (entry.tlsMode === 'file') parts.push(`cert=${getTrojanCertPaths(entry).certPath}`)
      if ((entry.tlsMode || 'acme') === 'acme') {
        if (entry.dnsProvider) parts.push(`dns01=${entry.dnsProvider}`)
        if (splitDomains(entry.acmeDomains).length) parts.push(`acme=${splitDomains(entry.acmeDomains).join(',')}`)
      }
      return parts.join('  ')
    },
    editableFields: ['port', 'password', 'domain', 'tlsMode', 'certPath', 'keyPath', 'acmeGroup', 'acmeDomains', 'acmeEmail', 'acmeCa', 'dnsProvider'],
  },
  ss: {
    label: 'SS 2022',
    defaultPort: 20085,
    fields: [
      { name: 'port', type: 'number', default: 20085, prompt: '端口' },
      { name: 'method', type: 'string', default: '2022-blake3-aes-256-gcm', prompt: '加密方法' },
      { name: 'password', type: 'string', generate: () => generateRandomBase64(32), prompt: '密码' },
    ],
    buildServerInbound(entry) {
      return {
        type: 'shadowsocks', tag: getProtocolTag(entry), listen: '::',
        listen_port: entry.port,
        method: entry.method,
        password: entry.password,
      }
    },
    metaToBean(entry, ip) {
      const bean = new ShadowsocksBean()
      bean.serverAddress = ip
      bean.serverPort = entry.port
      bean.method = entry.method
      bean.password = entry.password
      bean.name = getProtocolTag(entry) || this.label
      return bean
    },
    summary(entry) {
      return `port=${entry.port}  method=${entry.method}`
    },
    editableFields: ['port', 'method', 'password'],
  },
}

// --- 元数据管理 ---

export function normalizeMeta(meta = {}) {
  const settings = meta.settings || {}
  const protocols = Array.isArray(meta.protocols)
    ? meta.protocols.map(entry => {
      if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) return entry
      const tag = getProtocolTag(entry)
      return tag ? { ...entry, tag } : entry
    })
    : []
  return {
    ...meta,
    ip: typeof meta.ip === 'string' ? meta.ip : '',
    protocols,
    settings: {
      ...settings,
      serverLogTimestamp: settings.serverLogTimestamp === true ? true : DEFAULT_SERVER_SETTINGS.serverLogTimestamp,
      serverLogFile: typeof settings.serverLogFile === 'string' ? settings.serverLogFile : DEFAULT_SERVER_SETTINGS.serverLogFile,
    },
  }
}

async function loadMeta(metaPath) {
  const p = metaPath || DEFAULT_META_PATH
  try {
    const raw = await fs.readFile(p, 'utf-8')
    return normalizeMeta(JSON.parse(raw))
  } catch {
    return normalizeMeta()
  }
}

async function saveMeta(meta, metaPath) {
  const p = metaPath || DEFAULT_META_PATH
  await fs.mkdir(path.dirname(p), { recursive: true })
  await fs.writeFile(p, JSON.stringify(normalizeMeta(meta), null, 2), 'utf-8')
  sbtplLog(`saved to ${p}`)
}

// --- server 子命令 ---

function parseServerArgs(argv) {
  const result = { command: null, protocol: null, positional: [], values: {} }
  let i = 0
  // subcommand
  if (i < argv.length && !argv[i].startsWith('-')) {
    result.command = argv[i++]
  }
  // protocol (for add/remove)
  if (i < argv.length && !argv[i].startsWith('-')) {
    result.protocol = argv[i++]
  }
  // parse remaining as flags
  const remaining = argv.slice(i)
  const parsed = parseArgs({
    args: remaining,
    options: {
      'port': { type: 'string' },
      'domain': { type: 'string' },
      'method': { type: 'string' },
      'password': { type: 'string' },
      'uuid': { type: 'string' },
      'tag': { type: 'string' },
      'ip': { type: 'string' },
      'meta': { type: 'string' },
      'tls-mode': { type: 'string' },
      'cert-path': { type: 'string' },
      'key-path': { type: 'string' },
      'acme-domain': { type: 'string' },
      'acme-group': { type: 'string' },
      'acme-email': { type: 'string' },
      'acme-ca': { type: 'string' },
      'dns-provider': { type: 'string' },
      'dns-option': { type: 'string', multiple: true },
      'output-dir': { type: 'string', short: 'o' },
    },
    strict: false,
  })
  result.values = parsed.values
  result.positional = parsed.positionals
  return result
}

function getMetaPath(values) {
  return values.meta || DEFAULT_META_PATH
}

// Field names are camelCase while flags are kebab-case: --tls-mode -> tlsMode.
function readFlag(values, name) {
  const kebab = name.replace(/[A-Z]/g, char => `-${char.toLowerCase()}`)
  return values[name] ?? values[kebab]
}

function applyAcmeFlags(entry, values) {
  if (entry.type !== 'trojan') return
  if (values['acme-domain'] !== undefined) entry.acmeDomains = values['acme-domain']
  if (values['acme-email'] !== undefined) entry.acmeEmail = values['acme-email']
  if (values['acme-ca'] !== undefined) entry.acmeCa = values['acme-ca']
  if (values['dns-provider'] !== undefined) entry.dnsProvider = values['dns-provider']
  if (values['dns-option'] !== undefined) entry.dnsOptions = parseDnsOptions(values['dns-option'])
}

export function getLocalIpFromInterfaces(interfaces = os.networkInterfaces()) {
  for (const entries of Object.values(interfaces)) {
    for (const entry of entries || []) {
      const isIPv4 = entry.family === 'IPv4' || entry.family === 4
      if (isIPv4 && !entry.internal && entry.address) {
        return entry.address
      }
    }
  }
  return ''
}

function getLocalIp() {
  return getLocalIpFromInterfaces()
}

export function resolveServerIpInput(answer, currentIp, options = {}) {
  const {
    autoDetectIfEmpty = false,
    detectLocalIp = getLocalIp,
  } = options
  const ip = answer.trim()
  if (ip) {
    return { changed: true, ip, autoDetected: false }
  }

  if (autoDetectIfEmpty) {
    const detectedIp = detectLocalIp()
    if (detectedIp) {
      return { changed: true, ip: detectedIp, autoDetected: true }
    }
  }

  return { changed: false, ip: currentIp, autoDetected: false }
}

function getShareLink(entry, ip) {
  const reg = PROTOCOL_REGISTRY[entry.type]
  if (!reg) return null
  const bean = reg.metaToBean(entry, ip)
  return bean.toUri()
}

function printShareLinks(meta) {
  if (!meta.protocols.length) return
  console.log('\n--- Share Links ---')
  meta.protocols.forEach((entry, i) => {
    const reg = PROTOCOL_REGISTRY[entry.type]
    if (!reg) return
    const link = getShareLink(entry, meta.ip)
    console.log(`\n[${i + 1}. ${getProtocolTag(entry)}]`)
    console.log(link)
  })
}

export function buildServerLog(settings = {}) {
  const logFile = typeof settings.serverLogFile === 'string' ? settings.serverLogFile.trim() : ''
  const log = {
    level: 'info',
    timestamp: settings.serverLogTimestamp === true,
  }
  if (logFile) log.output = logFile
  return log
}

function nixString(value) {
  return JSON.stringify(value).replaceAll('${', '\\${')
}

// Renders plain objects/arrays as a Nix expression. "@path" option values become
// "{ _secret = ...; }", which services.sing-box inlines at unit start.
function nixValue(value, indent = 0) {
  const pad = ' '.repeat(indent)
  const inner = ' '.repeat(indent + 2)
  if (typeof value === 'string') {
    return value.startsWith('@') ? `{ _secret = ${nixString(value.slice(1))}; }` : nixString(value)
  }
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (Array.isArray(value)) {
    if (!value.length) return '[ ]'
    return `[\n${value.map(item => `${inner}${nixValue(item, indent + 2)}`).join('\n')}\n${pad}]`
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value)
    if (!entries.length) return '{ }'
    return `{\n${entries.map(([key, item]) => `${inner}${key} = ${nixValue(item, indent + 2)};`).join('\n')}\n${pad}}`
  }
  return 'null'
}

async function serverAdd(protocol, values, metaPath) {
  const reg = PROTOCOL_REGISTRY[protocol]
  if (!reg) {
    sbtplErr(`unknown protocol: ${protocol}. supported: ${Object.keys(PROTOCOL_REGISTRY).join(', ')}`)
    process.exit(1)
  }

  const meta = await loadMeta(metaPath)

  if (!meta.ip) {
    sbtplErr('server IP not set. use: sbtpl server set --ip <addr>')
    process.exit(1)
  }

  // check duplicate
  if (meta.protocols.some(p => p.type === protocol)) {
    sbtplErr(`${protocol} already exists. remove it first or use a different protocol`)
    process.exit(1)
  }

  // build entry from fields
  const entry = { type: protocol }
  for (const field of reg.fields) {
    if (field.when && !field.when(entry)) continue
    const provided = readFlag(values, field.name)
    if (provided !== undefined) {
      entry[field.name] = field.type === 'number' ? safeParseInt(provided, field.default) : provided
    } else if (field.generate) {
      entry[field.name] = field.generate()
    } else if (field.default !== undefined) {
      entry[field.name] = field.default
    } else if (field.required) {
      sbtplErr(`--${field.name} is required for ${protocol}`)
      process.exit(1)
    }
  }
  try {
    entry.tag = validateProtocolTag(values.tag ?? getProtocolTag(entry), meta.protocols)
    applyAcmeFlags(entry, values)
  } catch (error) {
    sbtplErr(error.message)
    process.exit(1)
  }

  // protocol-specific validation
  if (protocol === 'trojan') {
    const trojanProblem = validateTrojanEntry(entry)
    if (trojanProblem) {
      sbtplErr(trojanProblem)
      process.exit(1)
    }
  }

  meta.protocols.push(entry)
  await saveMeta(meta, metaPath)

  sbtplLog(`added ${reg.label}: ${reg.summary(entry)}`)
  const link = getShareLink(entry, meta.ip)
  console.log(`\n${link}`)
}

async function serverRemove(protocol, metaPath) {
  const meta = await loadMeta(metaPath)
  const idx = meta.protocols.findIndex(p => p.type === protocol)
  if (idx === -1) {
    sbtplErr(`${protocol} not found in config`)
    process.exit(1)
  }
  const removed = meta.protocols.splice(idx, 1)[0]
  await saveMeta(meta, metaPath)
  sbtplLog(`removed ${PROTOCOL_REGISTRY[protocol]?.label || protocol}`)
}

async function serverList(metaPath) {
  const meta = await loadMeta(metaPath)
  if (!meta.ip) {
    console.log('No server configured. use: sbtpl server set --ip <addr>')
    return
  }
  if (!meta.protocols.length) {
    console.log(`Server: ${meta.ip}\nNo protocols configured. use: sbtpl server add <protocol>`)
    return
  }
  console.log(`Server: ${meta.ip}\n`)
  meta.protocols.forEach((entry, i) => {
    const reg = PROTOCOL_REGISTRY[entry.type]
    if (!reg) return
    console.log(`${i + 1}. [${getProtocolTag(entry)}] ${reg.label}  ${reg.summary(entry)}`)
  })
  printShareLinks(meta)
}

async function serverSet(values, metaPath) {
  const meta = await loadMeta(metaPath)
  if (values.ip) {
    meta.ip = values.ip
    sbtplLog(`server IP set to ${values.ip}`)
  }
  await saveMeta(meta, metaPath)
}

// File-mode entries read certificates owned by another account (security.acme),
// so the generated module has to grant the group membership explicitly.
function getFileCertGroup(meta) {
  const entry = meta.protocols.find(item => item.type === 'trojan' && item.tlsMode === 'file')
  return entry ? (entry.acmeGroup || 'acme') : ''
}

async function resolveProviderSecrets(providers) {
  const resolved = []
  for (const provider of providers) {
    const copy = JSON.parse(JSON.stringify(provider))
    const challenge = copy.dns01_challenge
    if (challenge) {
      for (const [key, value] of Object.entries(challenge)) {
        if (typeof value !== 'string' || !value.startsWith('@')) continue
        const file = value.slice(1)
        try {
          challenge[key] = (await fs.readFile(file, 'utf-8')).trim()
        } catch (error) {
          sbtplErr(`cannot read dns option ${key} from ${file}: ${error.message}`)
          process.exit(1)
        }
      }
    }
    resolved.push(copy)
  }
  return resolved
}

async function serverGen(metaPath, outputDir) {
  const meta = await loadMeta(metaPath)
  if (!meta.ip || !meta.protocols.length) {
    sbtplErr('no server IP or protocols configured')
    process.exit(1)
  }

  for (const entry of meta.protocols) {
    if (entry.type !== 'trojan' || entry.tlsMode !== 'file') continue
    const { certPath, keyPath } = getTrojanCertPaths(entry)
    if (!certPath || !keyPath) {
      sbtplErr(`trojan ${getProtocolTag(entry)}: certificate path is missing, set --domain or --cert-path/--key-path`)
      process.exit(1)
    }
  }

  const certificateProviders = meta.protocols
    .filter(entry => entry.type === 'trojan' && (entry.tlsMode || 'acme') === 'acme')
    .map(entry => buildAcmeProvider(entry))
  const jsonCertificateProviders = await resolveProviderSecrets(certificateProviders)
  // build server inbounds
  const inbounds = meta.protocols.map(entry => {
    const reg = PROTOCOL_REGISTRY[entry.type]
    const certificateProviderTag = entry.type === 'trojan' && (entry.tlsMode || 'acme') === 'acme'
      ? `${getProtocolTag(entry)}-acme`
      : undefined
    return reg.buildServerInbound(entry, certificateProviderTag)
  })
  const serverLog = buildServerLog(meta.settings)
  const serverConfig = {
    log: serverLog,
    inbounds,
    outbounds: [{ type: 'direct', tag: 'direct' }],
  }
  if (jsonCertificateProviders.length > 0) serverConfig.certificate_providers = jsonCertificateProviders

  // build client outbounds
  const clientOutboundTags = []
  const clientOutbounds = []
  meta.protocols.forEach(entry => {
    const reg = PROTOCOL_REGISTRY[entry.type]
    const bean = reg.metaToBean(entry, meta.ip)
    const outbound = buildSingboxOutbound(bean, {})
    clientOutboundTags.push(outbound.tag)
    clientOutbounds.push(outbound)
  })
  const clientConfig = {
    log: { level: 'info', timestamp: true },
    outbounds: [
      { type: 'selector', tag: 'proxy', outbounds: [...clientOutboundTags, 'direct'] },
      ...clientOutbounds,
      { type: 'direct', tag: 'direct' },
    ],
  }

  // build NixOS module
  const nixInbounds = inbounds.map(ib => {
    const lines = ['        {']
    lines.push(`          type = ${nixString(ib.type)};`)
    lines.push(`          tag = ${nixString(ib.tag)};`)
    lines.push(`          listen = ${nixString(ib.listen)};`)
    lines.push(`          listen_port = ${ib.listen_port};`)
    if (ib.type === 'shadowsocks') {
      lines.push(`          method = ${nixString(ib.method)};`)
      lines.push(`          password = ${nixString(ib.password)};`)
    } else if (ib.type === 'vmess') {
      lines.push(`          users = [ { uuid = ${nixString(ib.users[0].uuid)}; } ];`)
    } else if (ib.type === 'trojan') {
      lines.push(`          users = [ { password = ${nixString(ib.users[0].password)}; } ];`)
      lines.push(`          tls = {`)
      lines.push(`            enabled = true;`)
      if (ib.tls.server_name) lines.push(`            server_name = ${nixString(ib.tls.server_name)};`)
      if (ib.tls.certificate_provider) {
        lines.push(`            certificate_provider = ${nixString(ib.tls.certificate_provider)};`)
      } else {
        if (ib.tls.certificate_path) lines.push(`            certificate_path = ${nixString(ib.tls.certificate_path)};`)
        if (ib.tls.key_path) lines.push(`            key_path = ${nixString(ib.tls.key_path)};`)
      }
      lines.push(`          };`)
    }
    lines.push('        }')
    return lines.join('\n')
  }).join('\n')

  const nixLogLines = [
    '        level = "info";',
    `        timestamp = ${serverLog.timestamp ? 'true' : 'false'};`,
  ]
  if (serverLog.output) {
    nixLogLines.push(`        output = ${nixString(serverLog.output)};`)
  }
  const nixCertificateProviders = certificateProviders.length > 0
    ? `      certificate_providers = [
${certificateProviders.map(provider => `        ${nixValue(provider, 8)}`).join('\n')}
      ];
`
    : ''

  const certGroup = getFileCertGroup(meta)
  const nixExtraUsers = certGroup ? `\n  users.users.sing-box.extraGroups = [ ${nixString(certGroup)} ];\n` : ''

  const nixModule = `{ config, pkgs, ... }:
{
  services.sing-box = {
    enable = true;
    settings = {
      log = {
${nixLogLines.join('\n')}
      };
      inbounds = [
${nixInbounds}
      ];
      outbounds = [
        {
          type = "direct";
          tag = "direct";
        }
      ];
${nixCertificateProviders}    };
  };
${nixExtraUsers}}
`

  // write files
  const dir = outputDir || '.'
  await fs.mkdir(dir, { recursive: true })
  await fs.writeFile(path.join(dir, 'server-config.json'), JSON.stringify(serverConfig, null, 2), 'utf-8')
  await fs.writeFile(path.join(dir, 'client-config.json'), JSON.stringify(clientConfig, null, 2), 'utf-8')
  await fs.writeFile(path.join(dir, 'sing-box-server.nix'), nixModule, 'utf-8')

  sbtplLog(`output directory: ${dir}`)
  sbtplLog(`  server-config.json`)
  sbtplLog(`  client-config.json`)
  sbtplLog(`  sing-box-server.nix`)

  // TLS certificate hints
  for (const entry of meta.protocols) {
    if (entry.type !== 'trojan') continue
    if ((entry.tlsMode || 'acme') === 'acme') {
      const acmeDomains = getAcmeDomains(entry)
      if (entry.dnsProvider) {
        console.log(`\n${YELLOW}[提示]${RESET} Trojan acme 模式 (DNS-01/${entry.dnsProvider}): 将为 ${BOLD}${acmeDomains.join(', ')}${RESET} 申请证书，不需要开放 80/443`)
      } else {
        console.log(`\n${YELLOW}[提示]${RESET} Trojan acme 模式: 请确保 ${BOLD}${acmeDomains.join(', ')}${RESET} 已解析到本机且 80 端口可达，sing-box 启动时会自动申请证书`)
      }
    } else if (entry.tlsMode === 'self-signed') {
      console.log(`\n${YELLOW}[提示]${RESET} Trojan self-signed 模式: 需手动生成证书:`)
      console.log(`  sing-box generate tls-keypair tls -m 456`)
      console.log(`  产出 /etc/sing-box/tls.cer + /etc/sing-box/tls.key`)
    } else if (entry.tlsMode === 'file') {
      const { certPath, keyPath } = getTrojanCertPaths(entry)
      const domain = entry.domain || '<domain>'
      console.log(`\n${YELLOW}[提示]${RESET} Trojan file 模式: 证书由外部管理（如 NixOS security.acme）`)
      console.log(`  证书 ${certPath}`)
      console.log(`  私钥 ${keyPath}`)
      const group = entry.acmeGroup || 'acme'
      console.log(`  sing-box 非 root 运行时需读证书，生成的模块已写入:`)
      console.log(`    users.users.sing-box.extraGroups = [ "${group}" ];`)
      console.log(`  ${DIM}证书实际属组不是 ${group} 时用 --acme-group 改（如 nginx）${RESET}`)
      console.log(`  证书续期后重载:`)
      console.log(`    security.acme.certs."${domain}".reloadServices = [ "sing-box.service" ];`)
      console.log(`  ${DIM}443 已被 sing-box 占用，acme 只能用 HTTP-01 或 DNS-01 验证${RESET}`)
    }
  }

  printShareLinks(meta)
}

// --- 交互式菜单 ---

const ESC = '\x1b'
const CLEAR = `${ESC}[2J${ESC}[H`
const HIDE_CURSOR = `${ESC}[?25l`
const SHOW_CURSOR = `${ESC}[?25h`
const DIM = `${ESC}[2m`
const BOLD = `${ESC}[1m`
const CYAN = `${ESC}[36m`
const GREEN = `${ESC}[32m`
const YELLOW = `${ESC}[33m`
const RED = `${ESC}[31m`
const RESET = `${ESC}[0m`

function ask(rl, question) {
  return new Promise((resolve, reject) => {
    const onClose = () => reject(new Error('READLINE_CLOSED'))
    rl.once('close', onClose)
    try {
      rl.question(question, (answer) => {
        rl.removeListener('close', onClose)
        resolve(answer)
      })
    } catch {
      rl.removeListener('close', onClose)
      reject(new Error('READLINE_CLOSED'))
    }
  })
}

async function choose(rl, prompt, options) {
  if (prompt) console.log(`\n${BOLD}${prompt}${RESET}`)
  options.forEach((opt, i) => console.log(`  ${CYAN}${i + 1}${RESET}. ${opt}`))
  const answer = await ask(rl, `\n${YELLOW}> ${RESET}`)
  const idx = parseInt(answer, 10) - 1
  if (idx < 0 || idx >= options.length) {
    console.log(`${RED}无效选择${RESET}`)
    return null
  }
  return idx
}

function renderMenuHeader(meta) {
  const lines = []
  lines.push(`${BOLD}╔══════════════════════════════════════╗${RESET}`)
  lines.push(`${BOLD}║       sbtpl server 管理              ║${RESET}`)
  lines.push(`${BOLD}╚══════════════════════════════════════╝${RESET}`)
  lines.push('')
  lines.push(`  ${DIM}服务端${RESET} ${BOLD}${meta.ip || '未设置'}${RESET}  ${DIM}节点${RESET} ${BOLD}${meta.protocols.length}${RESET}`)
  if (meta.protocols.length) {
    lines.push('')
    meta.protocols.forEach((entry, i) => {
      const reg = PROTOCOL_REGISTRY[entry.type]
      lines.push(`  ${CYAN}${i + 1}${RESET}. ${GREEN}${reg?.label || entry.type}${RESET}  ${DIM}[${getProtocolTag(entry)}] ${reg?.summary(entry) || ''}${RESET}`)
    })
  }
  lines.push('')
  lines.push(`${DIM}──────────────────────────────────────${RESET}`)
  return lines.join('\n')
}

function renderStatus(msg, type = 'ok') {
  const color = type === 'ok' ? GREEN : type === 'err' ? RED : YELLOW
  return `${color}${msg}${RESET}`
}

async function interactiveAdd(rl, meta) {
  const protocols = Object.keys(PROTOCOL_REGISTRY)
  const labels = protocols.map(k => PROTOCOL_REGISTRY[k].label)
  const idx = await choose(rl, '选择协议:', labels)
  if (idx === null) return '按 Enter 继续...'

  const protocol = protocols[idx]
  const reg = PROTOCOL_REGISTRY[protocol]

  if (meta.protocols.some(p => p.type === protocol)) {
    return renderStatus(`${protocol} 已存在，请先删除`, 'err')
  }

  const entry = { type: protocol }
  for (const field of reg.fields) {
    if (field.when && !field.when(entry)) continue
    const defaultVal = field.generate ? '(自动生成)' : (field.default ?? '')
    const hint = defaultVal ? ` ${DIM}[${defaultVal}]${RESET}` : ''
    const answer = await ask(rl, `  ${field.prompt}${hint}: `)
    if (answer.trim()) {
      entry[field.name] = field.type === 'number' ? safeParseInt(answer.trim(), field.default) : answer.trim()
    } else if (field.generate) {
      entry[field.name] = field.generate()
    } else if (field.default !== undefined) {
      entry[field.name] = field.default
    } else if (field.required) {
      return renderStatus(`${field.prompt} 不能为空`, 'err')
    }
  }

  if (protocol === 'trojan' && (entry.tlsMode || 'acme') === 'acme') {
    const acmeAnswer = await ask(rl, `  证书域名 ${DIM}(逗号分隔，泛域名用 *.x.y，留空=${entry.domain || 'domain'})${RESET}: `)
    if (acmeAnswer.trim()) entry.acmeDomains = acmeAnswer.trim()
    const emailAnswer = await ask(rl, `  ACME 邮箱 ${DIM}(留空跳过)${RESET}: `)
    if (emailAnswer.trim()) entry.acmeEmail = emailAnswer.trim()
    const caAnswer = await ask(rl, `  ACME CA ${DIM}(留空=letsencrypt，可填 zerossl 或 URL)${RESET}: `)
    if (caAnswer.trim()) entry.acmeCa = caAnswer.trim()
    const dnsAnswer = await ask(rl, `  DNS-01 提供商 ${DIM}(cloudflare/alidns/acmedns，留空=HTTP-01)${RESET}: `)
    if (dnsAnswer.trim()) {
      entry.dnsProvider = dnsAnswer.trim()
      const optionAnswer = await ask(rl, `  DNS 参数 ${DIM}(k=v,k=v，值写 @/path 表示从文件读取)${RESET}: `)
      if (optionAnswer.trim()) {
        try {
          entry.dnsOptions = parseDnsOptions(optionAnswer.trim())
        } catch (error) {
          return renderStatus(error.message, 'err')
        }
      }
    }
  }

  // protocol-specific validation
  if (protocol === 'trojan') {
    const trojanProblem = validateTrojanEntry(entry)
    if (trojanProblem) return renderStatus(trojanProblem, 'err')
  }

  const defaultTag = getProtocolTag(entry)
  const tagAnswer = await ask(rl, `  节点 tag ${DIM}[默认: ${defaultTag}]${RESET}: `)
  try {
    entry.tag = validateProtocolTag(tagAnswer.trim() || defaultTag, meta.protocols)
  } catch (error) {
    return renderStatus(error.message, 'err')
  }

  meta.protocols.push(entry)
  const link = getShareLink(entry, meta.ip)
  return renderStatus(`已添加 ${reg.label}: ${reg.summary(entry)}`) + `\n\n  ${DIM}share link:${RESET}\n  ${link}`
}

async function interactiveRemove(rl, meta) {
  if (!meta.protocols.length) return renderStatus('没有可删除的节点', 'warn')
  const labels = meta.protocols.map((e) => {
    const reg = PROTOCOL_REGISTRY[e.type]
    return `[${getProtocolTag(e)}] ${reg?.label || e.type}  ${reg?.summary(e) || ''}`
  })
  const idx = await choose(rl, '选择要删除的节点:', labels)
  if (idx === null) return null
  const removed = meta.protocols.splice(idx, 1)[0]
  return renderStatus(`已删除 ${PROTOCOL_REGISTRY[removed.type]?.label || removed.type}`)
}

async function interactiveModify(rl, meta) {
  if (!meta.protocols.length) return renderStatus('没有可修改的节点', 'warn')
  const labels = meta.protocols.map((e) => {
    const reg = PROTOCOL_REGISTRY[e.type]
    return `[${getProtocolTag(e)}] ${reg?.label || e.type}  ${reg?.summary(e) || ''}`
  })
  const idx = await choose(rl, '选择要修改的节点:', labels)
  if (idx === null) return null

  const entry = meta.protocols[idx]
  const reg = PROTOCOL_REGISTRY[entry.type]
  if (!reg) return null

  const editableFields = [...reg.editableFields, 'tag']
  const fieldIdx = await choose(rl, '选择修改项:', editableFields)
  if (fieldIdx === null) return null

  const fieldName = editableFields[fieldIdx]
  const currentVal = entry[fieldName]
  const answer = await ask(rl, `  ${fieldName} ${DIM}[当前: ${currentVal}]${RESET}: `)
  if (!answer.trim()) return renderStatus('未修改', 'warn')

  if (fieldName === 'tag') {
    try {
      entry.tag = validateProtocolTag(answer.trim(), meta.protocols, entry)
    } catch (error) {
      return renderStatus(error.message, 'err')
    }
  } else {
    const fieldDef = reg.fields.find(f => f.name === fieldName)
    const previous = entry[fieldName]
    entry[fieldName] = fieldDef?.type === 'number' ? safeParseInt(answer.trim(), currentVal) : answer.trim()
    if (entry.type === 'trojan') {
      const trojanProblem = validateTrojanEntry(entry)
      if (trojanProblem) {
        entry[fieldName] = previous
        return renderStatus(trojanProblem, 'err')
      }
    }
  }
  const link = getShareLink(entry, meta.ip)
  return renderStatus(`已更新 ${fieldName} = ${entry[fieldName]}`) + `\n\n  ${link}`
}

async function interactiveSetIp(rl, meta, options = {}) {
  const answer = await ask(rl, `  服务端 IP ${DIM}[当前: ${meta.ip || '未设置'}]${RESET}: `)
  const result = resolveServerIpInput(answer, meta.ip, options)
  if (result.changed) {
    meta.ip = result.ip
    const prefix = result.autoDetected ? '已自动获取本机 IP' : '服务端 IP 已设置为'
    return renderStatus(`${prefix} ${meta.ip}`)
  }
  if (options.autoDetectIfEmpty) {
    return renderStatus('未输入，且无法自动获取本机 IP', 'warn')
  }
  return renderStatus('未修改', 'warn')
}

async function interactiveSetServerLogTimestamp(rl, meta) {
  const current = meta.settings.serverLogTimestamp
  const action = await choose(rl, `服务端日志时间戳 ${DIM}[当前: ${current ? '开启' : '关闭'}]${RESET}:`, [
    '开启',
    '关闭',
    '返回',
  ])
  if (action === null || action === 2) return null

  const nextValue = action === 0
  if (nextValue === current) return renderStatus('未修改', 'warn')

  meta.settings.serverLogTimestamp = nextValue
  return renderStatus(`服务端日志时间戳已${nextValue ? '开启' : '关闭'}`)
}

async function interactiveSetServerLogFile(rl, meta) {
  const current = meta.settings.serverLogFile || '未设置'
  const answer = await ask(rl, `  服务端日志文件 ${DIM}[当前: ${current}，留空清除]${RESET}: `)
  const nextValue = answer.trim()

  if (nextValue === meta.settings.serverLogFile) return renderStatus('未修改', 'warn')

  meta.settings.serverLogFile = nextValue
  if (!nextValue) return renderStatus('服务端日志文件已清除')
  return renderStatus(`服务端日志文件已设置为 ${nextValue}`)
}

async function interactiveSoftwareSettings(rl, meta) {
  const action = await choose(rl, '软件设置:', [
    '设置服务端 IP',
    '服务端日志时间戳',
    '服务端日志文件',
    '返回',
  ])

  switch (action) {
    case 0:
      return interactiveSetIp(rl, meta)
    case 1:
      return interactiveSetServerLogTimestamp(rl, meta)
    case 2:
      return interactiveSetServerLogFile(rl, meta)
    case 3:
    case null:
      return null
    default:
      return renderStatus('无效选择', 'err')
  }
}

async function serverInteractive(metaPath) {
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  let meta = await loadMeta(metaPath)
  let statusMsg = ''

  try {
    // 首次运行，设置 IP
    if (!meta.ip) {
      process.stdout.write(CLEAR)
      console.log(renderMenuHeader(meta))
      console.log(`\n  ${BOLD}首次使用，请设置服务端 IP${RESET}\n`)
      statusMsg = await interactiveSetIp(rl, meta, { autoDetectIfEmpty: true })
      await saveMeta(meta, metaPath)
    }

    let running = true
    while (running) {
      process.stdout.write(CLEAR)
      console.log(renderMenuHeader(meta))
      if (statusMsg) {
        console.log(`\n  ${statusMsg}`)
        statusMsg = ''
      }

      const action = await choose(rl, '', [
        '添加节点',
        '查看节点',
        '修改节点',
        '删除节点',
        '软件设置',
        '生成配置文件',
        '退出',
      ])

      switch (action) {
        case 0:
          statusMsg = await interactiveAdd(rl, meta)
          if (statusMsg && !statusMsg.includes('已存在') && !statusMsg.includes('不能为空'))
            await saveMeta(meta, metaPath)
          break
        case 1:
          process.stdout.write(CLEAR)
          console.log(renderMenuHeader(meta))
          printShareLinks(meta)
          await ask(rl, `\n${DIM}按 Enter 返回...${RESET}`)
          break
        case 2:
          statusMsg = await interactiveModify(rl, meta)
          if (statusMsg?.includes('已更新')) await saveMeta(meta, metaPath)
          break
        case 3:
          statusMsg = await interactiveRemove(rl, meta)
          if (statusMsg?.includes('已删除')) await saveMeta(meta, metaPath)
          break
        case 4:
          statusMsg = await interactiveSoftwareSettings(rl, meta)
          if (statusMsg?.includes('已')) await saveMeta(meta, metaPath)
          break
        case 5:
          const dirAnswer = await ask(rl, `  输出目录 ${DIM}[默认: 当前目录]${RESET}: `)
          await serverGen(metaPath, dirAnswer.trim() || '.')
          statusMsg = renderStatus('配置文件已生成')
          break
        case 6:
          running = false
          break
          default:
          statusMsg = renderStatus('无效选择', 'err')
          break
      }
    }
  } catch (e) {
    if (e.message !== 'READLINE_CLOSED') throw e
  } finally {
    rl.close()
    process.stdout.write(SHOW_CURSOR)
    console.log(`\n${DIM}再见!${RESET}`)
  }
}

// --- server 命令分发 ---

// --- 入口 ---

import { realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const isMainModule = (() => {
  try {
    return process.argv[1] && realpathSync(process.argv[1]) === __filename
  } catch {
    return false
  }
})()

if (isMainModule) {
  serverDispatch(process.argv.slice(2))
}

// --- server 命令分发 ---

export async function serverDispatch(argv) {
  const args = parseServerArgs(argv)
  const metaPath = getMetaPath(args.values)

  switch (args.command) {
    case 'add':
      if (!args.protocol) {
        sbtplErr('usage: sbtpl server add <protocol> [--tag ...] [--port ...] [--domain ...] [--tls-mode ...]')
        process.exit(1)
      }
      await serverAdd(args.protocol, args.values, metaPath)
      break
    case 'remove':
    case 'rm':
      if (!args.protocol) {
        sbtplErr('usage: sbtpl server remove <protocol>')
        process.exit(1)
      }
      await serverRemove(args.protocol, metaPath)
      break
    case 'list':
    case 'ls':
      await serverList(metaPath)
      break
    case 'set':
      await serverSet(args.values, metaPath)
      break
    case 'gen':
      await serverGen(metaPath, args.values['output-dir'])
      break
    default:
      await serverInteractive(metaPath)
      break
  }
}
