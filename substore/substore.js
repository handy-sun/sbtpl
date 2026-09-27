// ./store.js#type=1&name=机场&outbound=@～all|all-auto@～hk|hk-auto-～港|hk|hongkong|kong kong|🇭🇰@～tw|tw-auto-～台|tw|taiwan|🇹🇼@～jp|jp-auto-～日本|jp|japan|🇯🇵@～sg|sg-auto-～^(?!.*(?:us)).*(新|sg|singapore|🇸🇬)@～us|us-auto-～美|us|unitedstates|united states|🇺🇸

// !! 注意：不需要的参数不要输入
// 示例说明
// 读取 名称为 "机场" 的 组合订阅 中的节点(单订阅不需要设置 type 参数)
// 把 所有节点插入匹配 /all|all-auto/i 的 outbound 中(跟在 @ 后面, ～ 表示忽略大小写, 不筛选节点不需要给 - )
// 把匹配 /港|hk|hongkong|kong kong|🇭🇰/i  (跟在 - 后面, ～ 表示忽略大小写) 的节点插入匹配 /hk|hk-auto/i 的 outbound 中
// ...
// 可选参数: includeUnsupportedProxy 包含官方/商店版不支持的协议 SSR. 用法: `&includeUnsupportedProxy=true`
// 可选参数: ipv6 启用 TUN IPv6 地址(默认关闭). 用法: `&ipv6=true`

// 支持传入订阅 URL. 参数为 url. 记得 url 需要 encodeURIComponent.
// 例如: http://a.com?token=123 应使用 url=http%3A%2F%2Fa.com%3Ftoken%3D123

// ruleset 参数: 修改 route rules 中的出站
// 格式: ruleset=出站标签-匹配内容@出站标签-匹配内容...
// 例如: ruleset=@⚡UrlTest-～(github|google)@🌐Proxy-～openai
// 表示: 找到包含 "github|google" 的规则(大小写不区分)，将其 outbound 改为 "⚡UrlTest"
//      找到包含 "openai" 的规则(大小写不区分)，将其 outbound 改为 "🌐Proxy"

// ⚠️ 如果 outbounds 为空, 自动创建 COMPATIBLE(direct) 并插入 防止报错
const compatible_outbound = {
  tag: 'COMPATIBLE',
  type: 'direct',
}

const default_mixport = 2334
const default_ctrlapi = 9090

const tun_tag = 'tun-in'
// tun 的默认配置stack为mixed: https://sing-box.sagernet.org/zh/configuration/inbound/tun/#stack
const tun_inbound = {
  type: 'tun',
  tag: tun_tag,
  address: [ '172.19.0.1/30' ],
  mtu: 9000,
  auto_route: true,
  strict_route: true,
}
const route_exclude_address = [
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.168.0.0/16",
  "255.255.255.255/32",
  "fe80::/10",
  "240e::/20"
]

log(`🚀 开始`)

let { type, name, outbound, ruleset, includeUnsupportedProxy, url, ctrlapi, mixport, tun, linux, icmp, android, ipv6, output } = $arguments
const ipv6Enabled = ipv6 === true || /^(1|true|yes|on)$/i.test(String(ipv6))

log(`传入参数 type: ${type}, name: ${name}, outbound: ${outbound}, ruleset: ${ruleset}, includeUnsupportedProxy: ${includeUnsupportedProxy}, url: ${url}, ctrlapi: ${ctrlapi}, mixport: ${mixport}, tun: ${tun}, linux: ${linux}, icmp: ${icmp}, android: ${android}, ipv6: ${ipv6Enabled}, output=${output};`)

type = /^1$|col|组合/i.test(type) ? 'collection' : 'subscription'

log(`⓵ 解析配置文件`)
let config
try {
  config = JSON.parse($content ?? $files[0])
} catch (e) {
  log(`${e.message ?? e}`)
  throw new Error('配置文件不是合法的 JSON')
}

// 参数未输入，如果开启tun, 修改为非default值以防止和本机的sing-box端口重复
ctrlapi = ctrlapi ? ctrlapi : (tun ? 8790 : default_ctrlapi)
log(`最终 ctrlapi=${ctrlapi}`)
if (ctrlapi != default_ctrlapi) {
  log(`⓵.⓶.⓵  clash_api后台控制界面 端口替换`)
  config.experimental.clash_api.external_controller = `[::]:${ctrlapi}`
  log(`📝 更新 experimental.clash_api.external_controller: ${config.experimental.clash_api.external_controller}`)
}

// 同上条注释
mixport = mixport ? mixport : (tun ? 2134 : default_mixport)
log(`最终 mixport=${mixport}`)
if (mixport != default_mixport) {
  log(`⓵.⓶.⓶  mix入站 端口替换`)
  config.inbounds[0].listen_port = mixport // WARN: HardCode! 默认第一个入站是 mix入站(如果不是需要手动调整代码)
  log(`📝 更新 inbounds[0](即 Mix入站).listen_port: ${JSON.stringify(config.inbounds[0])}`)
}

if (tun) {
  log(`⓵.⓷  tun 配置`)
  tun_inbound.address = [
    '172.19.0.1/30',
    ...(ipv6Enabled ? ['fdfe:dcba:9876::1/126'] : []),
  ]
  if (ipv6Enabled) log(`📝 开启了 tun 的 IPv6 地址`)
  if (config.route.rules[0]?.action === 'sniff') { // 默认开头一个规则是sniff的, 这里添加它的 inbound 为 tun_tag
    if (android) {
      config.inbounds.push(tun_inbound)
    } else {
      tun_inbound.route_exclude_address = route_exclude_address
      log(`📝 开启了 tun 的 route_exclude_address 功能`)
      if (linux) {
        const linux_tun_inbound = tun_inbound
        linux_tun_inbound.auto_redirect = true
        log(`📝 开启了 tun 的 auto_redirect(仅Linux支持) 功能`)
        config.inbounds.push(linux_tun_inbound)
      } else  {
        config.inbounds.push(tun_inbound)
      }
    }

    config.route.rules[0].inbound = tun_tag
    log(`📝 更新 route.rules[0]: ${JSON.stringify(config.route.rules[0])}`)
  }
}

if (icmp) {
  // network: icmp 需要 sing-box >= 1.13.0, 1.12 中该规则永远不会匹配
  log(`⓵.⓸  ⚠️ sing-box 1.12 不支持 icmp 路由, 忽略 icmp 参数`)
}

if (ruleset) {
  log(`⓵.⓹  ruleset 处理 ruleset 参数: 修改 route rules 中的出站`)
  const rulesetRules = ruleset
    .split('@')
    .filter(i => i)
    .map(i => {
      let [outboundPattern, matchPattern] = i.split('-')
      return [outboundPattern, matchPattern]
    })
    .filter(([outboundPattern, matchPattern]) => outboundPattern && matchPattern)

  log(`解析到要修改的规则数: ${rulesetRules.length}`)

  // 遍历 route rules，查找匹配的规则并修改 outbound
  config.route.rules.forEach((rule, index) => {
    rulesetRules.forEach(([outboundPattern, matchPattern]) => {
      const matchRegex = convert2RegExp(matchPattern)
      if (ruleContains(rule, matchRegex)) {
        const oldOutbound = rule.outbound
        rule.outbound = outboundPattern
        log(`📝 规则 #${index} 包含 "${matchRegex}", 出站从 "${oldOutbound}" 改为 "${outboundPattern}"`)
      }
    })
  })
}

if (android) {
  config.route.override_android_vpn = true
  log(`📝 开启了仅android支持的 route.override_android_vpn 功能`)
}

if (output) {
  let trimStr = output.trim()
  if (trimStr === "") {
    delete config.log.output
    delete config.log.timestamp
    log(`📝 删除了log.output 和 log.timestamp`)
  } else {
    config.log.output = trimStr
    config.log.timestamp = true
    log(`📝 修改了log.output: ${config.log.output}, log.timestamp: true`)
  }
}

log(`⓶ 获取订阅`)

let proxies
if (url) {
  log(`直接从 URL ${url} 读取订阅`)
  proxies = await produceArtifact({
    name,
    type,
    platform: 'sing-box',
    produceType: 'internal',
    produceOpts: {
      'include-unsupported-proxy': includeUnsupportedProxy,
    },
    subscription: {
      name,
      url,
      source: 'remote',
    },
  })
} else {
  log(`将读取名称为 ${name} 的 ${type === 'collection' ? '组合' : ''}订阅`)
  proxies = await produceArtifact({
    name,
    type,
    platform: 'sing-box',
    produceType: 'internal',
    produceOpts: {
      'include-unsupported-proxy': includeUnsupportedProxy,
    },
  })
}

// Hysteria v1 nodes emitted with the 1.14 QUIC field names need to be
// converted back to the legacy fields before appending to a 1.12 config.
proxies = proxies.map(normalizeProxy)

log(`⓷ outbound 规则解析`)
const outboundRules = outbound
  .split('@')
  .filter(i => i)
  .map(i => {
    let [outboundPattern, tagPattern = '.*'] = i.split('-')
    const tagRegex = convert2RegExp(tagPattern)
    log(`匹配 - ${tagRegex} 的节点将插入匹配 🌀 ${convert2RegExp(outboundPattern)} 的 outbound 中`)
    return [outboundPattern, tagRegex]
  })

log(`⓸ outbound 插入节点`)
config.outbounds.map(outboundItem => {
  outboundRules.map(([outboundPattern, tagRegex]) => {
    const outboundRegex = convert2RegExp(outboundPattern)
    if (outboundRegex.test(outboundItem.tag)) {
      if (!Array.isArray(outboundItem.outbounds)) {
        outboundItem.outbounds = []
      }
      const tags = getTags(proxies, tagRegex)
      log(`📝 ${outboundItem.tag} 匹配 ${outboundRegex}, 插入 ${tags.length} 个 - 匹配 ${tagRegex} 的节点`)
      outboundItem.outbounds.push(...tags)
    }
  })
})

log(`⓹ 空 outbounds 检查`)
config.outbounds.map(outboundItem => {
  outboundRules.map(([outboundPattern, tagRegex]) => {
    if (outboundItem.type.toLowerCase() !== "direct") {
      if (!Array.isArray(outboundItem.outbounds)) {
        outboundItem.outbounds = []
      }
      if (outboundItem.outbounds.length === 0) {
        log(`📝 ${outboundItem.tag} 的 outbounds 为空, 自动插入 🌐Proxy`)
        outboundItem.outbounds.push('🌐Proxy')
      }
    }
  })
})

const wireGuardEndpoints = proxies
  .filter(proxy => proxy.type === 'wireguard')
  .map(toWireGuardEndpoint)
const proxyOutbounds = proxies.filter(proxy => proxy.type !== 'wireguard')

config.outbounds.push(...proxyOutbounds)
if (wireGuardEndpoints.length > 0 || Array.isArray(config.endpoints)) {
  config.endpoints = [...(config.endpoints || []), ...wireGuardEndpoints]
}

$content = JSON.stringify(config, null, 2)

log(`结束`)

// ----------------- 辅助函数 -----------------
function getTags(proxies, regex) {
  return (regex ? proxies.filter(p => regex.test(p.tag)) : proxies).map(p => p.tag)
}
function toWireGuardEndpoint(proxy) {
  if (Array.isArray(proxy.peers) && !proxy.server && !proxy.peer_public_key) {
    return proxy
  }

  const peer = {
    address: proxy.server,
    port: proxy.server_port,
    public_key: proxy.peer_public_key,
    allowed_ips: ['0.0.0.0/0', '::/0'],
  }
  if (proxy.pre_shared_key) peer.pre_shared_key = proxy.pre_shared_key
  if (proxy.reserved) peer.reserved = normalizeReserved(proxy.reserved)

  return {
    type: 'wireguard',
    tag: proxy.tag,
    system: proxy.system_interface,
    name: proxy.interface_name,
    mtu: proxy.mtu,
    address: proxy.local_address,
    private_key: proxy.private_key,
    peers: [peer],
  }
}
function normalizeProxy(proxy) {
  if (!proxy || proxy.type !== 'hysteria') return proxy

  const normalized = { ...proxy }
  if (normalized.disable_mtu_discovery === undefined
    && normalized.disable_path_mtu_discovery !== undefined) {
    normalized.disable_mtu_discovery = normalized.disable_path_mtu_discovery
  }
  if (normalized.recv_window_conn === undefined
    && normalized.stream_receive_window !== undefined) {
    normalized.recv_window_conn = normalized.stream_receive_window
  }
  if (normalized.recv_window === undefined
    && normalized.connection_receive_window !== undefined) {
    normalized.recv_window = normalized.connection_receive_window
  }

  delete normalized.disable_path_mtu_discovery
  delete normalized.stream_receive_window
  delete normalized.connection_receive_window
  // sing-box 1.12 only accepts byte counts as integers for these fields
  for (const key of ['recv_window_conn', 'recv_window']) {
    if (normalized[key] !== undefined) normalized[key] = parseMemoryBytes(normalized[key])
  }
  return normalized
}
function parseMemoryBytes(value) {
  if (typeof value !== 'string') return value

  // same units as sing byteformats.MemoryBytes: every prefix is 1024-based
  const match = value.trim().match(/^(\d+)\s*([kmgt]?)(?:i?b)?$/i)
  if (!match) return value
  const power = ['', 'k', 'm', 'g', 't'].indexOf(match[2].toLowerCase())
  return Number(match[1]) * 1024 ** power
}
function normalizeReserved(value) {
  if (Array.isArray(value)) return value.map(Number)
  if (typeof value !== 'string') return value

  const trimmed = value.trim()
  const numbers = trimmed.match(/^\[?\s*\d+\s*(?:,\s*\d+\s*){2}\]?$/)
  if (numbers) return trimmed.replace(/[\[\]\s]/g, '').split(',').map(Number)
  return value
}
function log(v) {
  console.log(`[sing-box 📦] ${v}`)
}
function convert2RegExp(rulePattern) {
  return new RegExp(rulePattern.replace('~', ''), rulePattern.includes('~') ? 'i' : undefined)
}
// 检查规则是否包含指定内容
function ruleContains(rule, matchRegex) {
  if (!rule || !matchRegex) return false
  // 检查 rule_set 字段
  if (rule.rule_set) {
    const ruleSets = Array.isArray(rule.rule_set) ? rule.rule_set : [rule.rule_set]

    for (const rs of ruleSets) {
      let oneRule = String(rs).toLowerCase()
      if (matchRegex.test(oneRule)) {
        return true
      }
    }
  }
  return false
}
