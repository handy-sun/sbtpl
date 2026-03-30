const default_mixport = 2334
const default_clapi = 9090
const args =
  typeof $arguments !== 'undefined'
    ? $arguments
    : {
        type: 0,
        name: '_',
        tun: false,
        mixport: default_mixport,
        clapi: default_clapi,
        nightly: false,
        linux: false,
      }
const compatible_outbound = {
  tag: 'COMPATIBLE',
  type: 'direct',
}
const tun_inbound = {
  type: 'tun',
  tag: 'tun-in',
  address: [ '172.19.0.1/30', 'fdfe:dcba:9876::1/126' ],
  mtu: 9000,
  auto_route: true,
  strict_route: true,
}

function sblog(v) {
  console.log(`[📦sing-box] ${v}`)
}
function getTags(proxies, regex) {
  return (regex ? proxies.filter(p => regex.test(p.tag)) : proxies).map(p => p.tag)
}

console.log('[🚀sing-box] 开始...... args:', args)
// 如果是直接在软件中粘贴脚本的，就手动修改下面这几个变量实现自定义配置
// 没设置并且开启tun的话，mixed和clash_api的端口会自动设为2134和8790
let {
  type = args.type || 0,
  name = args.name || '_',
  tun = /^1$|true/i.test(args.tun) ? true : false,
  mixport = args.mixport || tun ? 2134 : default_mixport,
  clapi = args.clapi || tun ? 8790 : default_clapi,
  nightly = /^1$|true/i.test(args.nightly) ? true : false,
  linux = /^1$|true/i.test(args.linux) ? true : false,
} = args
sblog(`最终传入参数: { type: ${type}, name: ${name}, tun: ${tun}, mixport: ${mixport}, clapi: ${clapi}, nightly: ${nightly}, linux: ${linux} }`)
let config = JSON.parse($files[0])
let proxies = await produceArtifact({
  name,
  type: /^1$|col/i.test(type) ? 'collection' : 'subscription',
  platform: 'sing-box',
  produceType: 'internal',
})

if (clapi != default_clapi) {
  config.experimental.clash_api.external_controller = `[::]:${clapi}`
  sblog(`更新 experimental.clash_api.external_controller: ${config.experimental.clash_api.external_controller}`)
}
if (mixport != default_mixport) {
  config.inbounds[0].listen_port = mixport
  sblog(`更新 inbounds[0].listen_port: ${mixport}`)
}

config.outbounds.push(...proxies)

config.outbounds.map(i => {
  if (['🌐Proxy'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies))
  }
  if (['⚡UrlTest'].includes(i.tag)) {
    i.outbounds.push(...getTags(proxies))
  }
})

let compatible
config.outbounds.forEach(outbound => {
  if (Array.isArray(outbound.outbounds) && outbound.outbounds.length === 0) {
    if (!compatible) {
      config.outbounds.push(compatible_outbound)
      compatible = true
    }
    outbound.outbounds.push(compatible_outbound.tag)
  }
});

if (tun === "1" || tun === true) {
  if (config.route.rules[0]?.action === 'sniff') {
    if (linux === "1" || linux === true) {
      const linux_tun_inbound = tun_inbound
      linux_tun_inbound.auto_redirect = true
      sblog(`开启了 tun 的 auto_redirect(仅Linux支持) 功能`)
      config.inbounds.push(linux_tun_inbound)
    } else {
      config.inbounds.push(tun_inbound)
    }
    config.route.rules[0].inbound = 'tun-in'
    sblog(`更新 route.rules[0]: ${JSON.stringify(config.route.rules[0])}`)
  }
}

if (nightly === "1" || nightly === true) {
  config.route.rules.unshift({
    "network": "icmp",
    "outbound": "🎯Direct"
  })
  sblog(`头部插入了icmp直连 route.rules[0]: ${JSON.stringify(config.route.rules[0])}`)
}

$content = JSON.stringify(config, null, 2)
