# sbtpl

[![npm version](https://img.shields.io/npm/v/sbtpl.svg)](https://www.npmjs.com/package/sbtpl)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

sing-box 1.14 配置生成器 — 将代理订阅链接转换为 sing-box 兼容的 JSON 配置。

## 功能特性

- 支持多种代理协议：VMess/VLESS、Trojan、Shadowsocks、Socks、HTTP、Hysteria、TUIC、WireGuard、SSH、AnyTLS
- 从订阅链接自动解析节点
- 生成完整的 sing-box 客户端配置
- 支持 TUN 模式（Windows/Linux/Android）
- 支持自定义模板
- 提供服务端配置管理功能
- 零依赖，纯 Node.js 实现

## 安装

```bash
npm install -g sbtpl
```

或者使用 npx 直接运行：

```bash
npx sbtpl [options]
```

## 使用

### 基本用法

```bash
sbtpl -s '<订阅链接>' -o config.json
```

### 常用选项

| 参数 | 缩写 | 说明 |
|------|------|------|
| `--subscribe-link` | `-s` | 订阅链接或原始内容（支持多订阅，用 `;` 或换行分隔） |
| `--subscription-file` | `-f` | 本地订阅文件路径 |
| `--policy-filter` | `-p` | 节点策略筛选规则 |
| `--output-file` | `-o` | 输出文件路径，不指定则输出到 stdout |
| `--template` | `-t` | 自定义模板 JSON 文件路径 |
| `--tun` | | 启用 TUN 模式 |
| `--controller-port` | `-c` | clash_api 控制端口 |
| `--mixed-port` | `-m` | 混合代理端口 |
| `--log-file` | `-l` | 日志文件路径，设为空字符串禁用 |
| `--android` | | Android 模式 |
| `--linux` | | Linux TUN 模式 |
| `--ipv6` | | 显式启用 TUN IPv6 地址（默认关闭） |
| `--windows` | | Windows TUN 模式 |
| `--icmp` | | ICMP 透传 |

### 示例

**生成基本配置：**
```bash
sbtpl -s 'https://example.com/subscription' -o config.json
```

**生成 TUN 模式配置：**
```bash
sbtpl -s 'https://example.com/subscription' --tun --icmp -o config.json
```

**生成 Windows TUN 配置：**
```bash
sbtpl -s 'https://example.com/subscription' --tun --icmp --windows -o config.json
```

**生成 Linux TUN 配置：**
```bash
sbtpl -s 'https://example.com/subscription' --tun --linux -o config.json
```

**生成带 IPv6 的 Linux TUN 配置：**
```bash
sbtpl -s 'https://example.com/subscription' --tun --linux --ipv6 -o config.json
```

**生成 Android TUN 配置：**
```bash
sbtpl -s 'https://example.com/subscription' --tun --android -o config.json
```

**使用策略过滤：**
```bash
sbtpl -s 'https://example.com/subscription' -p '@🌐Proxy-~^(?!.*(aote|流量|到期|过滤|官网)).*$' -o config.json
```

**使用自定义模板：**
```bash
sbtpl -s 'https://example.com/subscription' -t my-template.json -o config.json
```

### 服务端配置管理

sbtpl 还提供服务端配置管理功能，用于生成 sing-box 服务端配置：

```bash
# 交互式菜单
sbtpl server

# 设置服务器 IP
sbtpl server set --ip 1.2.3.4

# 添加协议
sbtpl server add vmess
sbtpl server add vmess --tag edge-vmess
sbtpl server add trojan --domain yourdomain.com
sbtpl server add trojan --tls-mode file --domain yourdomain.com   # 用 NixOS security.acme 的证书
sbtpl server add ss --port 8388

# 查看配置
sbtpl server list

# 生成配置文件
sbtpl server gen -o ./output
```

#### 服务端子命令

| 命令 | 说明 |
|------|------|
| (无参数) | 进入交互式菜单 |
| `add <protocol> [--tag <tag>]` | 添加协议配置；tag 唯一，默认使用 `协议-端口`，并用于服务端 inbound 与客户端 outbound |
| `remove <protocol>` | 删除协议配置 |
| `list` | 查看所有配置及 share links |
| `set --ip <addr>` | 设置服务器 IP |
| `gen [-o <dir>]` | 生成服务端/客户端配置文件及 NixOS 模块 |

已有元数据会在下一次保存时补充默认 tag。

#### Trojan TLS 模式

| `--tls-mode` | 证书来源 |
|------|------|
| `acme`（默认） | sing-box 内置 ACME，启动时自动申请，使用顶层 `certificate_providers` |
| `self-signed` | 手动生成，固定读 `/etc/sing-box/tls.cer` + `/etc/sing-box/tls.key`，客户端会关闭证书校验 |
| `file` | 读取外部管理的证书，默认 `/var/lib/acme/<domain>/fullchain.pem` + `key.pem`，可用 `--cert-path` / `--key-path` 覆盖；证书属组用 `--acme-group` 指定（默认 `acme`），会写进生成的 `users.users.sing-box.extraGroups` |

`file` 模式配合 NixOS `security.acme`（证书由 systemd 定时续期，sing-box 不再自己申请）：

```nix
security.acme = {
  acceptTerms = true;
  defaults.email = "you@example.com";
  certs."example.com" = {
    group = "nginx";          # 证书属组，写 --acme-group nginx
    dnsProvider = "cloudflare";
    extraDomainNames = [ "*.example.com" ];
    reloadServices = [ "sing-box.service" ];
  };
};

# sing-box 以非 root 运行时需要读 640 的证书；gen 会按 --acme-group 自动写入这一行
users.users.sing-box.extraGroups = [ "nginx" ];
```


DNS-01（泛域名证书，不依赖 NixOS acme）：

```bash
sbtpl server add trojan \
  --domain vpn.647792.xyz \
  --acme-domain '*.647792.xyz,647792.xyz' \
  --acme-email you@example.com \
  --dns-provider cloudflare \
  --dns-option api_token=@/run/secrets/cf-token
```

| 参数 | 说明 |
|------|------|
| `--acme-domain` | 证书里要签的名字，逗号分隔，支持 `*.x.y`；留空默认取 `--domain` |
| `--acme-email` | ACME 账户邮箱 |
| `--acme-ca` | `letsencrypt`（默认）/ `zerossl` / 自定义 CA 的 URL |
| `--dns-provider` | `cloudflare` / `alidns` / `acmedns`；配置后强制走 DNS-01，不再需要 80 端口 |
| `--dns-option` | 可重复的 `k=v`，值以 `@` 开头表示从文件读取 |

各提供商的 `--dns-option` 字段：

- `cloudflare`：`api_token`（必填）、`zone_token`（可选）
- `alidns`：`access_key_id`、`access_key_secret`、`region_id`、`security_token`
- `acmedns`：`username`、`password`、`subdomain`、`server_url`

`--dns-option api_token=@/path` 的处理方式：

- `server-config.json`：生成时读取文件内容内联，因此 `gen` 必须能读到该文件
- `sing-box-server.nix`：写成 `{ _secret = "/path"; }`，由 `services.sing-box` 在启动前注入，token 不进 Nix store

`*.x.y` 这类泛域名只能走 DNS-01；只写 `--acme-domain '*.x.y'` 而不配 `--dns-provider` 会被直接拒绝。

Trojan 走 TLS over TCP：`listen` 只开 TCP 端口，UDP 流量（QUIC/DNS 等）由 Trojan 协议封装在 TLS 连接里转发，因此防火墙只需放行 `tcp/443`。

## 策略过滤格式

策略过滤使用以下格式：
```
@outboundTag-tagRegex...
```

示例：`@🌐Proxy@⚡UrlTest-~^(?!.*(流量|套餐|重置)).*$`

- `@` 分隔规则组
- `-` 前是目标 outbound 标签的正则，后是节点标签的筛选正则
- `~` 前缀表示忽略大小写

## 配置模板

sbtpl 使用 `substore/template.base.json` + `substore/template.js` 从公用配置生成三种 JSON 模板：

- `template.json`：FakeIP DNS
- `real-dns.json`：真实 DNS
- `real-dns-nosniff.json`：真实 DNS，不添加 sniff/DNS 劫持规则

修改公用配置或模式差异后，运行 `npm run generate:templates` 更新 JSON 产物。默认模板包含：
- DNS 配置（fakeip）
- 入站配置（mixed + 可选 TUN）
- 路由规则（17 组基于 rule_set 的规则）
- 预定义出站选择器（🎯Direct、🌐Proxy、🎮Steam、💬AI、🚀LowLatency、⚡UrlTest）

你可以使用 `-t` 参数指定自定义模板。

## 支持的协议

- VMess/VLESS
- Trojan
- Shadowsocks（含插件）
- Socks4/4a/5
- HTTP/HTTPS
- Hysteria 1&2
- TUIC
- WireGuard
- SSH
- AnyTLS（sing-box >= 1.12）

sing-box 1.14 兼容说明：远程 rule-set 使用共享 `http_clients`；WireGuard 节点写入顶层 `endpoints`；Hysteria v1 使用新的 QUIC 字段；服务端 Trojan ACME 使用顶层 certificate provider。

## 开发

### 项目结构

```
sbtpl/
├── node/              # CLI 工具 (Node.js ESM)
│   ├── base.js        # 主入口 — 客户端配置生成
│   ├── server.js      # server 子命令 — 服务端配置管理
│   ├── package.json   # 仅声明 type:module
│   └── Justfile       # just 任务定义
└── substore/          # Sub-Store 脚本
    ├── substore.js    # Sub-Store artifact 脚本
    ├── template.base.json # 公用模板源
    ├── template.js    # 公用模板与模式生成器
    └── *.json         # 供 CLI/Sub-Store 直接使用的生成模板
```

### 本地开发

```bash
# 克隆仓库
git clone https://github.com/handy-sun/sbtpl.git
cd sbtpl

# 直接运行
node node/base.js -s '<订阅链接>' -o config.json

# 使用 just 任务
just tun
just windows-tun
just linux-tun
just android-tun
```

## 许可证

GPL-3.0 License

## 项目地址

- GitHub: https://github.com/handy-sun/sbtpl
- npm: https://www.npmjs.com/package/sbtpl
