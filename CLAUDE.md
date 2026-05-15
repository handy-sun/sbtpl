# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

sbtpl (sing-box template) — sing-box 配置生成器。将代理订阅链接转换为 sing-box 兼容的 JSON 配置。提供两种使用方式：Node.js CLI 工具 和 Sub-Store 脚本。

## 目录结构

```
sbtpl/
├── node/              # CLI 工具 (Node.js ESM)
│   ├── base.js        # 主入口（~2642 行）
│   ├── package.json   # 仅声明 type:module
│   ├── Justfile       # just 任务定义
│   └── windows-tun.json  # 示例输出
└── substore/          # Sub-Store 脚本
    ├── substore.js    # Sub-Store artifact 脚本
    └── template.json  # sing-box 配置模板
```

## 架构要点

### node/base.js — CLI 工具

核心流水线：订阅链接 → 解析 Bean → 构建 outbound → 注入模板 → 输出 JSON

代码分三大模块：

1. **Bean 模型**（约 720 行）：每种代理协议一个类（VMessBean, TrojanBean, ShadowsocksBean 等），继承自 AbstractBean。每个 Bean 有 `initializeDefaultValues()` 和 `toUri()`。
2. **链接解析器**（约 480 行）：`parseLink()` 根据协议分发到 `parseV2Ray()`、`parseShadowsocks()` 等函数。
3. **Sing-box Outbound 构建**（约 460 行）：`buildSingboxOutbound()` 根据 Bean 类型分发到 `buildSingboxVMess()`、`buildSingboxTrojan()` 等函数。`buildSingboxTLS()`、`buildSingboxMux()`、`buildSingboxStreamSettings()` 是共享构建块。
4. **反向转换**（约 380 行）：Outbound JSON → Bean → URI 链接（`parseSingboxOutbound()` → `toUri()`）。
5. **模板处理**（约 160 行）：`setTemplateValue()` 修改模板配置（端口、TUN、ICMP 等），`insertProxies()` 将解析出的节点注入 selector/urltest outbound。

### substore/substore.js — Sub-Store 脚本

与 base.js 功能类似但运行在 Sub-Store 环境：
- 使用 `$content`/`$arguments`/`$files` 全局变量替代 CLI args
- 使用 `produceArtifact()` API 替代 HTTP 订阅抓取
- 额外支持 `ruleset` 参数修改 route rules 出站
- 不包含解析/构建逻辑（复用 Sub-Store 内置转换能力）

### substore/template.json

sing-box 基础配置模板，包含：DNS（fakeip）、入站（mixed + 可选 TUN）、路由规则（27 条 rule_set 规则）、预定义出站选择器（🎯Direct、🌐Proxy、💬AI、🚀LowLatency、⚡UrlTest）。

## 支持协议

VMess/VLESS、Trojan、Shadowsocks（含插件）、Socks4/4a/5、HTTP/HTTPS、Hysteria 1&2、TUIC、WireGuard、SSH、AnyTLS（sing-box >= 1.12）

## 常用命令

```bash
# 基本用法（需替换订阅链接）
node base.js -s '<sub-link>' -p '<policy-filter>' -o config.json

# TUN 模式
node base.js -s '<sub-link>' -p '<policy-filter>' --tun --icmp -o config.json

# Windows TUN（gVisor 栈）
node base.js -s '<sub-link>' -p '<policy-filter>' --tun --icmp --windows -o config.json

# Linux TUN
node base.js -s '<sub-link>' -p '<policy-filter>' --tun --linux -o config.json

# Android 模式（TUN）
node base.js -s '<sub-link>' -p '<policy-filter>' --tun --android -o config.json

# 使用 just 任务
just tun
just windows-tun
just linux-tun
just android-tun
```

### CLI 参数

| 参数 | 缩写 | 说明 |
|------|------|------|
| `--subscribe-link` | `-s` | 订阅链接或原始内容（支持多订阅，用 `;` 或换行分隔） |
| `--subscription-file` | `-f` | 本地订阅文件路径（文件内容按订阅响应处理，支持多文件，用 `;` 或换行分隔） |
| `--policy-filter` | `-p` | 节点策略筛选规则，格式：`@outboundTag-tagRegex` |
| `--output-file` | `-o` | 输出文件路径，不指定则输出到 stdout |
| `--template` | `-t` | 自定义模板 JSON 文件路径，不指定则使用内置默认模板 |
| `--tun` | | 启用 TUN 模式 |
| `--controller-port` | `-c` | clash_api 控制端口 |
| `--mixed-port` | `-m` | 混合代理端口 |
| `--log-file` | `-l` | 日志文件路径，设为空字符串禁用 |
| `--android` | | Android 模式（override_android_vpn） |
| `--linux` | | Linux TUN（auto_redirect） |
| `--windows` | | Windows TUN（gVisor 栈） |
| `--icmp` | | ICMP 透传（sing-box >= 1.13） |

### policy-filter 格式

```
@outboundTag-tagRegex...
```

示例：`@🌐Proxy@⚡UrlTest-~^(?!.*(aote|流量|到期|过滤|官网)).*$`

- `@` 分隔规则组
- `-` 前是目标 outbound 标签的正则，后是节点标签的筛选正则
- `~` 前缀表示忽略大小写

## 注意

- 无测试框架，无第三方 npm 依赖
- 所有 `node/*.json` 被 .gitignore 排除（`node/package.json` 例外，已被 git track）
- 开发时用 `node base.js` 直接运行
