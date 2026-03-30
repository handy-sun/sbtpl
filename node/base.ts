import { parseArgs } from 'node:util'
import { readFile, writeFile } from 'node:fs/promises'
import { Resolver } from 'node:dns/promises'
import https from 'node:https'

const {
  values: {
    'url-link': urlLink,
    'output-file': outputFile,
  },
} = parseArgs({
  args: process.argv.slice(2),
  options: {
    'url-link': {
      type: 'string',
      short: 'u',
    },
    'output-file': {
      type: 'string',
      short: 'o',
    },
  },
})

if (!urlLink || !outputFile) {
  console.log('need 2 arguments')
  process.exit(1)
}

// const base64 = (await readFile(urlLink, { encoding: 'utf8' })).trim()

// const url = (await readFile(urlLink, { encoding: 'utf8' })).trim()
const { hostname, pathname, search } = new URL(urlLink)
const resolver = new Resolver()
resolver.setServers(['223.5.5.5'])
const address = await resolver.resolve4(hostname)
const ip = address[0]
const { promise, resolve, reject } = Promise.withResolvers<string>()
const req = https.request(
  {
    hostname: ip,
    port: 443,
    path: pathname + search,
    method: 'GET',
    headers: {
      Host: hostname,
    },
  },
  (res) => {
    let data = ''
    res.on('data', (chunk) => (data += chunk))
    res.on('end', () => resolve(data))
  },
)
req.on('error', reject)
req.end()

const base64 = await promise

// subscription 内容处理：Base64 -> UTF-8，防止中文节点名称乱码
const subText = Buffer.from(base64, 'base64').toString('utf8')
const nodes: (
  | {
      tag: string
      type: 'vmess'
      server: string
      server_port: number
      uuid: string
      alter_id: number
    }
  | {
      tag: string
      type: 'ss'
      server: string
      server_port: number
      method: string
      password: string
    }
)[] = []

subText
  .split(/\r?\n/)
  .forEach((s) => {
    if (!s) return
    const url = new URL(s)
    // console.log(s);
    // console.log(url);
    const type = url.protocol.replace(':', '')
    if (type === 'hysteria2') {
      console.log(url.host)
    }
    const decodeTag = (rawTag: string) => {
      try {
        return decodeURIComponent(rawTag)
      } catch {
        return rawTag
      }
    }

    if (type === 'vmess') {
      const config = Buffer.from(url.host, 'base64').toString('utf8')
      const { ps, port, id, aid, add } = JSON.parse(config) as {
        ps: string
        port: string
        id: string
        aid: number
        net: string
        type: string
        tls: string
        add: string
      }
      nodes.push({
        tag: decodeTag(ps),
        type: 'vmess' as const,
        server: add,
        server_port: Number.parseInt(port),
        uuid: id,
        alter_id: aid,
      })
    }
    if (type === 'ss') {
      const config = Buffer.from(url.host, 'base64').toString('utf8')
      const arr = config.split(':')
      const arr2 = arr[1]!.split('@')
      nodes.push({
        type: 'shadowsocks' as const,
        tag: decodeTag(url.hash.replace('#', '')),
        server: arr2[1]!,
        server_port: Number.parseInt(arr[2]!),
        method: arr[0]!,
        password: arr2[0]!,
      })
    }
  })

const tags = nodes.map((i) => i.tag)

const outbounds = [
  {
    type: 'direct',
    tag: 'direct',
  },
  {
    type: 'selector',
    tag: 'select',
    outbounds: ['auto', ...tags],
    interrupt_exist_connections: true,
  },
  {
    type: 'urltest',
    tag: 'auto',
    interval: '3m',
    outbounds: tags,
    interrupt_exist_connections: true,
  },
  ...nodes,
]

const json = JSON.stringify({
  log: {
    level: 'info',
  },
  dns: {
    servers: [
      {
        tag: 'dns-proxy',
        type: 'https',
        server: '1.1.1.1',
        detour: 'select',
      },
      {
        tag: 'dns-direct',
        type: 'quic',
        server: '223.6.6.6',
      },
    ],
    rules: [
      {
        type: 'logical',
        mode: 'or',
        rules: [
          {
            query_type: 'HTTPS',
          },
          {
            rule_set: ['geosite-category-ads-all'],
          },
        ],
        action: 'reject',
      },
      {
        clash_mode: 'Global',
        server: 'dns-proxy',
      },
      {
        clash_mode: 'Direct',
        server: 'dns-direct',
      },
      {
        rule_set: ['geosite-cn'],
        server: 'dns-direct',
      },
    ],
    strategy: 'ipv4_only',
    independent_cache: true,
  },
  inbounds: [
    {
      type: 'tun',
      tag: 'tun-in',
      address: [ '172.19.0.1/30', 'fdfe:dcba:9876::1/126' ],
      mtu: 9000,
      auto_route: true,
      strict_route: true,
    }
  ],
  outbounds,
  route: {
    default_domain_resolver: {
      server: 'dns-direct',
      strategy: 'ipv4_only',
    },
    final: 'select',
    rules: [
      {
        action: 'sniff',
        inbound: 'tun-in'
      },
      {
        type: 'logical',
        mode: 'or',
        rules: [
          {
            protocol: 'dns',
          },
          {
            port: 53,
          },
        ],
        action: 'hijack-dns',
      },
      {
        ip_is_private: true,
        outbound: "direct",
      },
      {
        type: 'logical',
        mode: 'or',
        rules: [
          {
            port: 853,
          },
          {
            network: 'udp',
            port: 443,
          },
          // {
          //   protocol: "stun",
          // },
        ],
        action: 'reject',
      },
      {
        clash_mode: 'Global',
        outbound: 'select',
      },
      {
        clash_mode: 'Direct',
        outbound: 'direct',
      },
      {
        action: 'resolve',
        strategy: 'ipv4_only',
      },
      {
        type: 'logical',
        mode: 'or',
        rules: [
          {
            rule_set: ['geosite-cn', 'geoip-cn'],
          },
        ],
        outbound: 'direct',
      },
    ],
    rule_set: [
      {
        type: 'remote',
        tag: 'geoip-cn',
        format: 'binary',
        url: 'https://ghfast.top/https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-cn.srs',
        download_detour: 'direct',
      },
      {
        type: 'remote',
        tag: 'geosite-cn',
        format: 'binary',
        url: 'https://ghfast.top/https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-cn.srs',
        download_detour: 'direct',
      },
      {
        type: 'remote',
        tag: 'geosite-category-ads-all',
        format: 'binary',
        url: 'https://ghfast.top/https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ads-all.srs',
      },
    ],
  },
  experimental: {
    cache_file: {
      enabled: true,
    },
    clash_api: {
      external_controller: '[::]:8790',
      external_ui: 'ui',
      external_ui_download_url:
        'https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip',
    },
  },
}, null, 2)

await writeFile(outputFile, json)

