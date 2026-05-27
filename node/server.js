import { parseArgs } from 'node:util'
import { createInterface } from 'node:readline'
import path from 'node:path'
import fs from 'fs/promises'

import {
  VMessBean, TrojanBean, ShadowsocksBean,
  buildSingboxOutbound,
  generateUUID, generateRandomBase64,
  sbtplLog, sbtplErr, safeParseInt,
} from './base.js'

// --- 服务端配置管理 ---

const DEFAULT_META_PATH = 'sbtpl-meta.json'

const PROTOCOL_REGISTRY = {
  vmess: {
    label: 'VMess',
    defaultPort: 20086,
    fields: [
      { name: 'port', type: 'number', default: 20086, prompt: '端口' },
      { name: 'uuid', type: 'string', generate: () => generateUUID(), prompt: 'UUID' },
    ],
    buildServerInbound(entry) {
      return {
        type: 'vmess', tag: 'vmess-in', listen: '::',
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
      { name: 'domain', type: 'string', required: true, prompt: '域名 (TLS server_name)' },
    ],
    buildServerInbound(entry) {
      return {
        type: 'trojan', tag: 'trojan-in', listen: '::',
        listen_port: entry.port,
        users: [{ password: entry.password }],
        tls: {
          enabled: true,
          server_name: entry.domain,
          certificate_path: '/var/lib/sing-box/cert.pem',
          key_path: '/var/lib/sing-box/priv.key',
        },
      }
    },
    metaToBean(entry, ip) {
      const bean = new TrojanBean()
      bean.serverAddress = ip
      bean.serverPort = entry.port
      bean.password = entry.password
      bean.sni = entry.domain
      bean.security = 'tls'
      bean.name = this.label
      return bean
    },
    summary(entry) {
      return `port=${entry.port}  domain=${entry.domain}`
    },
    editableFields: ['port', 'password', 'domain'],
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
        type: 'shadowsocks', tag: 'ss-in', listen: '::',
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

async function loadMeta(metaPath) {
  const p = metaPath || DEFAULT_META_PATH
  try {
    const raw = await fs.readFile(p, 'utf-8')
    return JSON.parse(raw)
  } catch {
    return { ip: '', protocols: [] }
  }
}

async function saveMeta(meta, metaPath) {
  const p = metaPath || DEFAULT_META_PATH
  await fs.writeFile(p, JSON.stringify(meta, null, 2), 'utf-8')
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
  const serverConfig = {
    log: { level: 'info', timestamp: true },
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
      lines.push(`            server_name = "${ib.tls.server_name}";`)
      lines.push(`            certificate_path = "${ib.tls.certificate_path}";`)
      lines.push(`            key_path = "${ib.tls.key_path}";`)
      lines.push(`          };`)
    }
    lines.push('        }')
    return lines.join('\n')
  }).join('\n')

  const nixModule = `{ config, pkgs, ... }:
{
  services.sing-box = {
    enable = true;
    settings = {
      log = {
        level = "info";
        timestamp = true;
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
  lines.push(`  ${DIM}服务器${RESET} ${BOLD}${meta.ip || '未设置'}${RESET}  ${DIM}协议${RESET} ${BOLD}${meta.protocols.length}${RESET}`)
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

  meta.protocols.push(entry)
  const link = getShareLink(entry, meta.ip)
  return renderStatus(`已添加 ${reg.label}: ${reg.summary(entry)}`) + `\n\n  ${DIM}share link:${RESET}\n  ${link}`
}

async function interactiveRemove(rl, meta) {
  if (!meta.protocols.length) return renderStatus('没有可删除的配置', 'warn')
  const labels = meta.protocols.map((e) => {
    const reg = PROTOCOL_REGISTRY[e.type]
    return `${reg?.label || e.type}  ${reg?.summary(e) || ''}`
  })
  const idx = await choose(rl, '选择要删除的配置:', labels)
  if (idx === null) return null
  const removed = meta.protocols.splice(idx, 1)[0]
  return renderStatus(`已删除 ${PROTOCOL_REGISTRY[removed.type]?.label || removed.type}`)
}

async function interactiveModify(rl, meta) {
  if (!meta.protocols.length) return renderStatus('没有可修改的配置', 'warn')
  const labels = meta.protocols.map((e) => {
    const reg = PROTOCOL_REGISTRY[e.type]
    return `${reg?.label || e.type}  ${reg?.summary(e) || ''}`
  })
  const idx = await choose(rl, '选择要修改的配置:', labels)
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

async function interactiveSetIp(rl, meta) {
  const answer = await ask(rl, `  服务器 IP ${DIM}[当前: ${meta.ip || '未设置'}]${RESET}: `)
  if (answer.trim()) {
    meta.ip = answer.trim()
    return renderStatus(`服务器 IP 已设置为 ${meta.ip}`)
  }
  return renderStatus('未修改', 'warn')
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
      console.log(`\n  ${BOLD}首次使用，请设置服务器 IP${RESET}\n`)
      statusMsg = await interactiveSetIp(rl, meta)
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
        '添加配置',
        '查看配置',
        '修改配置',
        '删除配置',
        '设置服务器 IP',
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
          statusMsg = await interactiveSetIp(rl, meta)
          await saveMeta(meta, metaPath)
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
