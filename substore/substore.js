// ./store.js#type=1&name=机场&outbound=@～all|all-auto@～hk|hk-auto-～港|hk|hongkong|kong kong|🇭🇰@～tw|tw-auto-～台|tw|taiwan|🇹🇼@～jp|jp-auto-～日本|jp|japan|🇯🇵@～sg|sg-auto-～^(?!.*(?:us)).*(新|sg|singapore|🇸🇬)@～us|us-auto-～美|us|unitedstates|united states|🇺🇸

// !! 注意：不需要的参数不要输入
// 示例说明
// 读取 名称为 "机场" 的 组合订阅 中的节点(单订阅不需要设置 type 参数)
// 把 所有节点插入匹配 /all|all-auto/i 的 outbound 中(跟在 @ 后面, ～ 表示忽略大小写, 不筛选节点不需要给 - )
// 把匹配 /港|hk|hongkong|kong kong|🇭🇰/i  (跟在 - 后面, ～ 表示忽略大小写) 的节点插入匹配 /hk|hk-auto/i 的 outbound 中
// ...
// 可选参数: includeUnsupportedProxy 包含官方/商店版不支持的协议 SSR. 用法: `&includeUnsupportedProxy=true`

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
  address: [ '172.19.0.1/30', 'fdfe:dcba:9876::1/126' ],
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
  "224.0.0.0/4",
  "240.0.0.0/4",
  "255.255.255.255/32",
  "fe80::/10",
  "fc00::/7",
  "ff01::/16",
  "ff02::/16",
  "ff03::/16",
  "ff04::/16",
  "ff05::/16",
  "240e::/20"
]

log(`🚀 开始`)

let { type, name, outbound, ruleset, includeUnsupportedProxy, url, ctrlapi, mixport, tun, linux, icmp, android, output } = $arguments

log(`传入参数 type: ${type}, name: ${name}, outbound: ${outbound}, ruleset: ${ruleset}, includeUnsupportedProxy: ${includeUnsupportedProxy}, url: ${url}, ctrlapi: ${ctrlapi}, mixport: ${mixport}, tun: ${tun}, linux: ${linux}, icmp: ${icmp}, android: ${android}, output=${output};`)

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
  log(`⓵.⓸  icmp 透传: (sing-box version>=1.13.0)`)
  config.route.rules.unshift({
    "network": "icmp",
    "outbound": icmp
  })
  log(`📝 头部插入了icmp直连, 当前route.rules[0]: ${JSON.stringify(config.route.rules[0])}`)
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
    log(`📝 删除了log.output`)
  } else {
    config.log.output = trimStr
    log(`📝 修改了log.output: ${config.log.output}`)
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

config.outbounds.push(...proxies)

$content = JSON.stringify(config, null, 2)

log(`结束`)

// ----------------- 辅助函数 -----------------
function getTags(proxies, regex) {
  return (regex ? proxies.filter(p => regex.test(p.tag)) : proxies).map(p => p.tag)
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
