# sbtpl

[![npm version](https://img.shields.io/npm/v/sbtpl.svg)](https://www.npmjs.com/package/sbtpl)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

sing-box 配置生成器 — 将代理订阅链接转换为 sing-box 兼容的 JSON 配置。

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
sbtpl server add trojan --domain yourdomain.com
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
| `add <protocol>` | 添加协议配置 |
| `remove <protocol>` | 删除协议配置 |
| `list` | 查看所有配置及 share links |
| `set --ip <addr>` | 设置服务器 IP |
| `gen [-o <dir>]` | 生成服务端/客户端配置文件及 NixOS 模块 |

## 策略过滤格式

策略过滤使用以下格式：
```
@outboundTag-tagRegex...
```

示例：`@🌐Proxy@⚡UrlTest-~^(?!.*(aote|流量|到期|过滤|官网)).*$`

- `@` 分隔规则组
- `-` 前是目标 outbound 标签的正则，后是节点标签的筛选正则
- `~` 前缀表示忽略大小写

## 配置模板

sbtpl 使用 JSON 模板生成配置。默认模板包含：
- DNS 配置（fakeip）
- 入站配置（mixed + 可选 TUN）
- 路由规则（27 条 rule_set 规则）
- 预定义出站选择器（🎯Direct、🌐Proxy、💬AI、🚀LowLatency、⚡UrlTest）

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
    └── template.json  # sing-box 配置模板
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