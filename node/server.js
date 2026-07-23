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
  serverLogLevel: 'info',
  serverLogTimestamp: false,
  serverLogFile: '',
}

export function buildServerInboundTag(protocol, port) {
  return `${protocol}-${port}`
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
        type: 'vmess', tag: buildServerInboundTag('vmess', entry.port), listen: '::',
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
      bean.name = this.label
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
      { name: 'tlsMode', type: 'string', default: 'acme', prompt: 'TLS 模式 (acme/self-signed)' },
      { name: 'domain', type: 'string', prompt: '域名 (TLS server_name)' },
    ],
    buildServerInbound(entry) {
      const tls = { enabled: true, server_name: entry.domain || '' }
      if (entry.tlsMode === 'self-signed') {
        tls.certificate_path = typeof entry.certificatePath === 'string' && entry.certificatePath.trim() !== ''
          ? entry.certificatePath
          : '/etc/sing-box/tls.cer'
        tls.key_path = typeof entry.keyPath === 'string' && entry.keyPath.trim() !== ''
          ? entry.keyPath
          : '/etc/sing-box/tls.key'
      } else {
        tls.acme = { domain: [entry.domain] }
      }
      return {
        type: 'trojan', tag: buildServerInboundTag('trojan', entry.port), listen: '::',
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
      bean.name = this.label
      return bean
    },
    summary(entry) {
      const parts = [`port=${entry.port}`]
      if (entry.domain) parts.push(`domain=${entry.domain}`)
      parts.push(`tls=${entry.tlsMode || 'acme'}`)
      return parts.join('  ')
    },
    editableFields: ['port', 'password', 'domain', 'tlsMode'],
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
        type: 'shadowsocks', tag: buildServerInboundTag('ss', entry.port), listen: '::',
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
      bean.name = this.label
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
  return {
    ...meta,
    ip: typeof meta.ip === 'string' ? meta.ip : '',
    protocols: Array.isArray(meta.protocols) ? meta.protocols : [],
    settings: {
      ...settings,
      serverLogLevel: typeof settings.serverLogLevel === 'string' && settings.serverLogLevel.trim() !== ''
        ? settings.serverLogLevel.trim()
        : DEFAULT_SERVER_SETTINGS.serverLogLevel,
      serverLogTimestamp: settings.serverLogTimestamp === true ? true : DEFAULT_SERVER_SETTINGS.serverLogTimestamp,
      serverLogFile: typeof settings.serverLogFile === 'string' ? settings.serverLogFile : DEFAULT_SERVER_SETTINGS.serverLogFile,
    },
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function requireNonEmptyString(value, field) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${field} must be a non-empty string`)
  }
  return value
}

function importInboundPort(inbound, index) {
  const port = inbound.listen_port
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`inbound ${index} listen_port must be an integer from 1 through 65535`)
  }
  return port
}

function importSingleUserCredential(inbound, index, credential) {
  if (!Array.isArray(inbound.users) || inbound.users.length !== 1) {
    throw new Error(`inbound ${index} users must contain exactly one entry`)
  }
  const user = inbound.users[0]
  if (!isPlainObject(user)) {
    throw new Error(`inbound ${index} users[0] must be an object`)
  }
  return requireNonEmptyString(user[credential], `inbound ${index} users[0].${credential}`)
}

function importTrojanTls(tls, index) {
  if (!isPlainObject(tls)) {
    throw new Error(`inbound ${index} tls must be an object`)
  }
  if (tls.enabled !== true) {
    throw new Error(`inbound ${index} tls.enabled must be true`)
  }

  const hasAcme = Object.hasOwn(tls, 'acme')
  const hasCertificate = Object.hasOwn(tls, 'certificate_path')
  const hasKey = Object.hasOwn(tls, 'key_path')
  if (hasAcme && (hasCertificate || hasKey)) {
    throw new Error(`inbound ${index} has mixed ACME and certificate TLS modes`)
  }

  const serverName = Object.hasOwn(tls, 'server_name')
    ? requireNonEmptyString(tls.server_name, `inbound ${index} tls.server_name`)
    : ''

  if (hasAcme) {
    if (!isPlainObject(tls.acme)) {
      throw new Error(`inbound ${index} tls.acme must be an object`)
    }
    if (!Array.isArray(tls.acme.domain)) {
      throw new Error(`inbound ${index} tls.acme.domain must be an array`)
    }
    const acmeDomain = tls.acme.domain.find(domain => (
      typeof domain === 'string' && domain.trim() !== ''
    ))
    if (acmeDomain === undefined) {
      throw new Error(`inbound ${index} tls.acme.domain must contain a non-empty string`)
    }
    const domain = serverName || acmeDomain
    return { tlsMode: 'acme', domain }
  }

  if (!hasCertificate && !hasKey) {
    throw new Error(`inbound ${index} tls must use ACME or certificate_path with key_path`)
  }
  const certificatePath = requireNonEmptyString(tls.certificate_path, `inbound ${index} tls.certificate_path`)
  const keyPath = requireNonEmptyString(tls.key_path, `inbound ${index} tls.key_path`)
  return {
    tlsMode: 'self-signed',
    domain: serverName,
    certificatePath,
    keyPath,
  }
}

function importServerLog(log) {
  if (log === undefined) {
    return { level: 'info', timestamp: false, output: '' }
  }
  if (!isPlainObject(log)) {
    throw new Error('log must be an object')
  }

  const imported = { level: 'info', timestamp: false, output: '' }
  if (Object.hasOwn(log, 'level')) {
    imported.level = requireNonEmptyString(log.level, 'log.level')
  }
  if (Object.hasOwn(log, 'timestamp')) {
    if (typeof log.timestamp !== 'boolean') {
      throw new Error('log.timestamp must be a boolean')
    }
    imported.timestamp = log.timestamp
  }
  if (Object.hasOwn(log, 'output')) {
    if (typeof log.output !== 'string') {
      throw new Error('log.output must be a string')
    }
    imported.output = log.output
  }
  return imported
}

export function importServerConfig(config, currentMeta = {}) {
  if (!isPlainObject(config)) {
    throw new Error('config root must be an object')
  }
  if (!Array.isArray(config.inbounds)) {
    throw new Error('config inbounds must be an array')
  }

  const importedLog = importServerLog(config.log)
  const protocols = []
  const warnings = []
  const importedTypes = new Set()
  const supportedTypes = new Map([
    ['vmess', 'vmess'],
    ['trojan', 'trojan'],
    ['shadowsocks', 'ss'],
  ])

  config.inbounds.forEach((inbound, index) => {
    const inboundType = isPlainObject(inbound) ? inbound.type : undefined
    const internalType = supportedTypes.get(inboundType)
    if (!internalType) {
      let typeLabel
      if (typeof inboundType === 'string') typeLabel = JSON.stringify(inboundType)
      else if (inboundType === undefined) typeLabel = '<missing>'
      else if (inboundType === null) typeLabel = 'null'
      else typeLabel = `<${Array.isArray(inboundType) ? 'array' : typeof inboundType}>`
      warnings.push(`inbound ${index}: unsupported type ${typeLabel}`)
      return
    }
    if (importedTypes.has(internalType)) {
      throw new Error(`inbound ${index} duplicates supported protocol type ${inboundType}`)
    }
    importedTypes.add(internalType)

    const port = importInboundPort(inbound, index)
    if (inboundType === 'vmess') {
      protocols.push({
        type: 'vmess',
        port,
        uuid: importSingleUserCredential(inbound, index, 'uuid'),
      })
      return
    }
    if (inboundType === 'trojan') {
      protocols.push({
        type: 'trojan',
        port,
        password: importSingleUserCredential(inbound, index, 'password'),
        ...importTrojanTls(inbound.tls, index),
      })
      return
    }
    protocols.push({
      type: 'ss',
      port,
      method: requireNonEmptyString(inbound.method, `inbound ${index} method`),
      password: requireNonEmptyString(inbound.password, `inbound ${index} password`),
    })
  })

  if (protocols.length === 0) {
    throw new Error('config contains no supported inbounds')
  }

  const baseMeta = isPlainObject(currentMeta) ? currentMeta : {}
  const currentSettings = isPlainObject(baseMeta.settings) ? baseMeta.settings : {}
  const meta = normalizeMeta({
    ...baseMeta,
    protocols,
    settings: {
      ...currentSettings,
      serverLogLevel: importedLog.level,
      serverLogTimestamp: importedLog.timestamp,
      serverLogFile: importedLog.output,
    },
  })

  return { meta, warnings }
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
      'ip': { type: 'string' },
      'meta': { type: 'string' },
      'tls-mode': { type: 'string' },
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
    console.log(`\n[${i + 1}. ${reg.label}]`)
    console.log(link)
  })
}

export function buildServerLog(settings = {}) {
  const logLevel = typeof settings.serverLogLevel === 'string' && settings.serverLogLevel.trim() !== ''
    ? settings.serverLogLevel.trim()
    : DEFAULT_SERVER_SETTINGS.serverLogLevel
  const logFile = typeof settings.serverLogFile === 'string' ? settings.serverLogFile.trim() : ''
  const log = {
    level: logLevel,
    timestamp: settings.serverLogTimestamp === true,
  }
  if (logFile) log.output = logFile
  return log
}

function nixString(value) {
  return JSON.stringify(value)
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
    if (values[field.name] !== undefined) {
      entry[field.name] = field.type === 'number' ? safeParseInt(values[field.name], field.default) : values[field.name]
    } else if (field.generate) {
      entry[field.name] = field.generate()
    } else if (field.default !== undefined) {
      entry[field.name] = field.default
    } else if (field.required) {
      sbtplErr(`--${field.name} is required for ${protocol}`)
      process.exit(1)
    }
  }

  // protocol-specific validation
  if (protocol === 'trojan') {
    if (entry.tlsMode !== 'acme' && entry.tlsMode !== 'self-signed') {
      sbtplErr('--tls-mode must be acme or self-signed')
      process.exit(1)
    }
    if (entry.tlsMode === 'acme' && !entry.domain) {
      sbtplErr('--domain is required when tls-mode is acme')
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
    console.log(`${i + 1}. ${reg.label}  ${reg.summary(entry)}`)
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

async function serverGen(metaPath, outputDir) {
  const meta = await loadMeta(metaPath)
  if (!meta.ip || !meta.protocols.length) {
    sbtplErr('no server IP or protocols configured')
    process.exit(1)
  }

  // build server inbounds
  const inbounds = meta.protocols.map(entry => {
    const reg = PROTOCOL_REGISTRY[entry.type]
    return reg.buildServerInbound(entry)
  })
  const serverLog = buildServerLog(meta.settings)
  const serverConfig = {
    log: serverLog,
    inbounds,
    outbounds: [{ type: 'direct', tag: 'direct' }],
  }

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
    lines.push(`          type = "${ib.type}";`)
    lines.push(`          tag = "${ib.tag}";`)
    lines.push(`          listen = "::";`)
    lines.push(`          listen_port = ${ib.listen_port};`)
    if (ib.type === 'shadowsocks') {
      lines.push(`          method = "${ib.method}";`)
      lines.push(`          password = "${ib.password}";`)
    } else if (ib.type === 'vmess') {
      lines.push(`          users = [ { uuid = "${ib.users[0].uuid}"; } ];`)
    } else if (ib.type === 'trojan') {
      lines.push(`          users = [ { password = "${ib.users[0].password}"; } ];`)
      lines.push(`          tls = {`)
      lines.push(`            enabled = true;`)
      if (ib.tls.server_name) lines.push(`            server_name = "${ib.tls.server_name}";`)
      if (ib.tls.acme) {
        lines.push(`            acme = {`)
        lines.push(`              domain = [ ${ib.tls.acme.domain.map(d => `"${d}"`).join(' ')} ];`)
        lines.push(`            };`)
      } else {
        if (ib.tls.certificate_path) lines.push(`            certificate_path = "${ib.tls.certificate_path}";`)
        if (ib.tls.key_path) lines.push(`            key_path = "${ib.tls.key_path}";`)
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
    };
  };
}
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
    if (entry.tlsMode === 'acme') {
      console.log(`\n${YELLOW}[提示]${RESET} Trojan acme 模式: 请确保 ${BOLD}${entry.domain}${RESET} 已解析到本机且 80 端口可达，sing-box 启动时会自动申请证书`)
    } else if (entry.tlsMode === 'self-signed') {
      console.log(`\n${YELLOW}[提示]${RESET} Trojan self-signed 模式: 需手动生成证书:`)
      console.log(`  sing-box generate tls-keypair tls -m 456`)
      console.log(`  产出 /etc/sing-box/tls.cer + /etc/sing-box/tls.key`)
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
      lines.push(`  ${CYAN}${i + 1}${RESET}. ${GREEN}${reg?.label || entry.type}${RESET}  ${DIM}${reg?.summary(entry) || ''}${RESET}`)
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

  // protocol-specific validation
  if (protocol === 'trojan') {
    if (entry.tlsMode !== 'acme' && entry.tlsMode !== 'self-signed') {
      return renderStatus('TLS 模式必须是 acme 或 self-signed', 'err')
    }
    if (entry.tlsMode === 'acme' && !entry.domain) {
      return renderStatus('acme 模式下域名不能为空', 'err')
    }
  }

  meta.protocols.push(entry)
  const link = getShareLink(entry, meta.ip)
  return renderStatus(`已添加 ${reg.label}: ${reg.summary(entry)}`) + `\n\n  ${DIM}share link:${RESET}\n  ${link}`
}

async function interactiveRemove(rl, meta) {
  if (!meta.protocols.length) return renderStatus('没有可删除的节点', 'warn')
  const labels = meta.protocols.map((e) => {
    const reg = PROTOCOL_REGISTRY[e.type]
    return `${reg?.label || e.type}  ${reg?.summary(e) || ''}`
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
    return `${reg?.label || e.type}  ${reg?.summary(e) || ''}`
  })
  const idx = await choose(rl, '选择要修改的节点:', labels)
  if (idx === null) return null

  const entry = meta.protocols[idx]
  const reg = PROTOCOL_REGISTRY[entry.type]
  if (!reg) return null

  const fieldIdx = await choose(rl, '选择修改项:', reg.editableFields)
  if (fieldIdx === null) return null

  const fieldName = reg.editableFields[fieldIdx]
  const currentVal = entry[fieldName]
  const answer = await ask(rl, `  ${fieldName} ${DIM}[当前: ${currentVal}]${RESET}: `)
  if (!answer.trim()) return renderStatus('未修改', 'warn')

  const fieldDef = reg.fields.find(f => f.name === fieldName)
  entry[fieldName] = fieldDef?.type === 'number' ? safeParseInt(answer.trim(), currentVal) : answer.trim()
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
        sbtplErr('usage: sbtpl server add <protocol> [--port ...] [--domain ...]')
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
