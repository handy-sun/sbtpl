#!/usr/bin/env node
import { parseArgs } from 'node:util'
import path from 'node:path'
import http from 'node:http'
import https from 'node:https'
import crypto from 'node:crypto'
import fs from 'fs/promises';
import { execSync } from 'node:child_process';

import { createTemplate } from '../substore/template.js'
import pkg from '../package.json' with { type: 'json' }

// --- 工具函数 --- [[[1

/**
 * Base64 解码函数
 * @param {string} str - Base64 编码的字符串
 * @returns {string} 解码后的字符串
 */
function b64Decode(str) {
  try {
    const safeStr = str.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - safeStr.length % 4) % 4);
    return Buffer.from(safeStr + padding, 'base64').toString('utf8');
  } catch (e) {
    return "";
  }
}

/**
 * Base64 编码函数
 * @param {string} str - 原始字符串
 * @param {boolean} urlSafe - 是否使用 URL 安全的编码
 * @returns {string} 编码后的字符串
 */
function b64Encode(str, urlSafe = false) {
  const encoded = Buffer.from(str, 'utf8').toString('base64');
  if (urlSafe) {
    return encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }
  return encoded;
}

/**
 * 按行或逗号分割字符串
 * @param {string} str - 输入字符串
 * @returns {string[]} 分割后的字符串数组
 */
function listByLineOrComma(str) {
  if (!str || typeof str !== 'string') return [];
  return str.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
}

/**
 * 安全地解析整数
 * @param {*} value - 要解析的值
 * @param {number} defaultValue - 默认值
 * @returns {number} 解析后的整数
 */
function safeParseInt(value, defaultValue = 0) {
  if (value === null || value === undefined) return defaultValue;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? defaultValue : parsed;
}

/**
 * 检查字符串是否为 IP 地址
 * @param {string} str - 输入字符串
 * @returns {boolean} 是否为 IP 地址
 */
function isIpAddress(str) {
  if (!str || typeof str !== 'string') return false;
  const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const ipv6Regex = /:/;
  return ipv4Regex.test(str) || ipv6Regex.test(str);
}

/**
 * 生成 WireGuard reserved 字段的 Base64 编码
 * @param {string} anyStr - 输入字符串
 * @returns {string} Base64 编码的字符串
 */
function genWgReserved(anyStr) {
  try {
    const list = anyStr.replace(/[\[\]\s]/g, '').split(',');
    if (list.length === 3) {
      const ba = new Uint8Array(3);
      for (let i = 0; i < 3; i++) {
        const num = parseInt(list[i], 10);
        if (isNaN(num)) return anyStr;
        ba[i] = num;
      }
      return Buffer.from(ba).toString('base64');
    }
    return anyStr;
  } catch (e) {
    return anyStr;
  }
}

/**
 * 检查端口字符串是否包含多个端口
 * @param {string} portStr - 端口字符串
 * @returns {boolean} 是否为多端口
 */
function isMultiPort(portStr) {
  if (!portStr) return false;
  return portStr.includes('-') || portStr.includes(',');
}

/**
 * 将跳跃端口转换为 sing-box 列表格式
 * @param {string} s - 端口字符串
 * @returns {string[]} 转换后的端口数组
 */
function hopPortsToSingboxList(s) {
  return s.split(',').map(it => {
    const pRange = it.replace('-', ':');
    return pRange.includes(':') ? pRange : null;
  }).filter(Boolean);
}

// --- 凭据生成 ---

function generateUUID() {
  return crypto.randomUUID()
}

function generateRandomBase64(byteLength) {
  return crypto.randomBytes(byteLength).toString('base64')
}

// --- Bean 类 ---

/**
 * 抽象 Bean 类
 */
class AbstractBean {
  constructor() {
    this.serverAddress = "127.0.0.1";
    this.serverPort = 1080;
    this.name = "";
  }

  /**
   * 初始化默认值
   */
  initializeDefaultValues() {
    if (!this.name) this.name = "";
    if (!this.serverAddress) this.serverAddress = "127.0.0.1";
    if (this.serverPort == null) this.serverPort = 1080;
  }

  /**
   * 获取显示名称
   * @returns {string} 显示名称
   */
  displayName() {
    return this.name || `${this.serverAddress}:${this.serverPort}`;
  }

  /**
   * 转换为 URI
   * @returns {string} URI 字符串
   */
  toUri() {
    throw new Error("toUri() not implemented for this bean type");
  }
}

/**
 * 标准 V2Ray Bean 类
 */
class StandardV2RayBean extends AbstractBean {
  constructor() {
    super();
    this.uuid = "";
    this.encryption = "";
    this.type = "tcp";
    this.host = "";
    this.path = "";
    this.security = "none";
    this.sni = "";
    this.alpn = "";
    this.utlsFingerprint = "";
    this.allowInsecure = false;
    this.realityPubKey = "";
    this.realityShortId = "";
    this.packetEncoding = 0;
    this.wsMaxEarlyData = 0;
    this.earlyDataHeaderName = "";
    this.certificates = "";
    this.enableECH = false;
    this.echConfig = "";
    this.enableMux = false;
    this.muxPadding = false;
    this.muxType = 0;
    this.muxConcurrency = 1;
  }

  /**
   * 初始化默认值
   */
  initializeDefaultValues() {
    super.initializeDefaultValues();
    if (!this.uuid) this.uuid = "";
    if (!this.type) this.type = "tcp";
    if (!this.host) this.host = "";
    if (!this.path) this.path = "";
    if (!this.security) this.security = "none";
    if (!this.sni) this.sni = "";
    if (!this.alpn) this.alpn = "";
    if (!this.utlsFingerprint) this.utlsFingerprint = "";
    if (this.allowInsecure == null) this.allowInsecure = false;
    if (!this.realityPubKey) this.realityPubKey = "";
    if (!this.realityShortId) this.realityShortId = "";
    if (this.packetEncoding == null) this.packetEncoding = 0;
    if (this.wsMaxEarlyData == null) this.wsMaxEarlyData = 0;
    if (!this.earlyDataHeaderName) this.earlyDataHeaderName = "";
    if (!this.certificates) this.certificates = "";
    if (this.enableECH == null) this.enableECH = false;
    if (!this.echConfig) this.echConfig = "";
    if (this.enableMux == null) this.enableMux = false;
    if (this.muxPadding == null) this.muxPadding = false;
    if (this.muxType == null) this.muxType = 0;
    if (this.muxConcurrency == null) this.muxConcurrency = 1;
  }

  /**
   * 检查是否使用 TLS
   * @returns {boolean} 是否使用 TLS
   */
  isTLS() {
    return this.security === 'tls' || this.security === 'reality';
  }

  /**
   * 转换为 URI
   * @param {boolean} isTrojan - 是否为 Trojan
   * @returns {string} URI 字符串
   */
  toUri(isTrojan = false) {
    const protocol = isTrojan ? 'trojan' : (this.isVLESS() ? 'vless' : 'vmess');

    if (protocol === 'vmess') {
      const vmessQRCode = {
        v: "2",
        ps: this.name,
        add: this.serverAddress,
        port: this.serverPort.toString(),
        id: this.uuid,
        aid: this.alterId.toString(),
        scy: this.encryption || "auto",
        net: this.type,
        type: "none",
        host: this.host,
        path: this.path,
        tls: this.isTLS() ? (this.realityPubKey ? "reality" : "tls") : "none",
        sni: this.sni,
        alpn: this.alpn,
        fp: this.utlsFingerprint
      };
      return `vmess://${b64Encode(JSON.stringify(vmessQRCode))}`;
    }

    const userInfo = isTrojan ? this.password : this.uuid;
    let link = `${protocol}://${encodeURIComponent(userInfo)}@${this.serverAddress}:${this.serverPort}`;
    const params = new URLSearchParams();

    if (this.type !== 'tcp') params.set('type', this.type);
    if (this.security !== 'none') {
      const securityType = this.realityPubKey ? 'reality' : this.security;
      params.set('security', securityType);
      if (this.sni) params.set('sni', this.sni);
      if (this.alpn) params.set('alpn', this.alpn);
      if (this.allowInsecure) params.set('allowInsecure', '1');
      if (this.utlsFingerprint) params.set('fp', this.utlsFingerprint);
      if (securityType === 'reality') {
        if (this.realityPubKey) params.set('pbk', this.realityPubKey);
        if (this.realityShortId) params.set('sid', this.realityShortId);
      }
    }

    if (this.isVLESS() && this.encryption && this.encryption !== 'auto') {
      params.set('flow', this.encryption);
    }

    if (this.type === 'ws' || this.type === 'http') {
      if (this.host) params.set('host', this.host);
      if (this.path) params.set('path', this.path);
    } else if (this.type === 'grpc') {
      if (this.path) params.set('serviceName', this.path);
    }

    const queryString = params.toString();
    if (queryString) {
      link += `?${queryString}`;
    }
    if (this.name) {
      link += `#${encodeURIComponent(this.name)}`;
    }
    return link;
  }

  isVLESS() {
    return false;
  }
}

/**
 * VMess Bean 类
 */
class VMessBean extends StandardV2RayBean {
  constructor() {
    super();
    this.alterId = 0;
  }

  /**
   * 初始化默认值
   */
  initializeDefaultValues() {
    super.initializeDefaultValues();
    if (this.alterId == null) this.alterId = 0;
    if (this.isVLESS()) {
      this.encryption = this.encryption || "";
    } else {
      this.encryption = this.encryption || "auto";
    }
  }

  /**
   * 检查是否为 VLESS
   * @returns {boolean} 是否为 VLESS
   */
  isVLESS() {
    return this.alterId === -1;
  }
}

/**
 * Trojan Bean 类
 */
class TrojanBean extends StandardV2RayBean {
  constructor() {
    super();
    this.password = "";
  }

  /**
   * 初始化默认值
   */
  initializeDefaultValues() {
    super.initializeDefaultValues();
    if (!this.security) this.security = "tls";
    if (!this.password) this.password = "";
  }

  /**
   * 转换为 URI
   * @returns {string} URI 字符串
   */
  toUri() {
    return super.toUri(true);
  }
}

/**
 * Shadowsocks Bean 类
 */
class ShadowsocksBean extends AbstractBean {
  constructor() {
    super();
    this.method = "aes-256-gcm";
    this.password = "";
    this.plugin = "";
    this.sUoT = false;
  }

  /**
   * 初始化默认值
   */
  initializeDefaultValues() {
    super.initializeDefaultValues();
    if (!this.method) this.method = "aes-256-gcm";
    if (!this.password) this.password = "";
    if (!this.plugin) this.plugin = "";
    if (this.sUoT == null) this.sUoT = false;
  }

  /**
   * 转换为 URI
   * @returns {string} URI 字符串
   */
  toUri() {
    const creds = b64Encode(`${this.method}:${this.password}`, true);
    let link = `ss://${creds}@${this.serverAddress}:${this.serverPort}`;
    const params = new URLSearchParams();
    if (this.plugin) {
      const pluginParts = this.plugin.split(';');
      const pluginName = pluginParts[0];
      const pluginOpts = pluginParts.slice(1).join(';');
      params.set('plugin', `${pluginName};${pluginOpts}`);
    }
    const queryString = params.toString();
    if (queryString) {
      link += `?${queryString}`;
    }
    if (this.name) {
      link += `#${encodeURIComponent(this.name)}`;
    }
    return link;
  }
}

/**
 * Socks Bean 类
 */
class SocksBean extends AbstractBean {
  constructor() {
    super();
    this.protocol = 2; // 0: SOCKS4, 1: SOCKS4a, 2: SOCKS5
    this.username = "";
    this.password = "";
    this.sUoT = false;
  }

  /**
   * 初始化默认值
   */
  initializeDefaultValues() {
    super.initializeDefaultValues();
    if (this.protocol == null) this.protocol = 2;
    if (!this.username) this.username = "";
    if (!this.password) this.password = "";
    if (this.sUoT == null) this.sUoT = false;
  }

  /**
   * 获取协议版本名称
   * @returns {string} 协议版本名称
   */
  protocolVersionName() {
    switch (this.protocol) {
      case 0:
        return "4";
      case 1:
        return "4a";
      default:
        return "5";
    }
  }

  /**
   * 转换为 URI
   * @returns {string} URI 字符串
   */
  toUri() {
    const protocolMap = {
      0: 'socks4',
      1: 'socks4a',
      2: 'socks'
    };
    const protocol = protocolMap[this.protocol] || 'socks';
    let userInfo = '';
    if (this.username) {
      userInfo += encodeURIComponent(this.username);
      if (this.password) {
        userInfo += `:${encodeURIComponent(this.password)}`;
      }
      userInfo += '@';
    }
    let link = `${protocol}://${userInfo}${this.serverAddress}:${this.serverPort}`;
    if (this.name) {
      link += `#${encodeURIComponent(this.name)}`;
    }
    return link;
  }
}

/**
 * HTTP Bean 类
 */
class HttpBean extends StandardV2RayBean {
  constructor() {
    super();
    this.username = "";
    this.password = "";
  }

  /**
   * 初始化默认值
   */
  initializeDefaultValues() {
    super.initializeDefaultValues();
    if (!this.username) this.username = "";
    if (!this.password) this.password = "";
  }

  /**
   * 转换为 URI
   * @returns {string} URI 字符串
   */
  toUri() {
    const protocol = this.isTLS() ? 'https' : 'http';
    let userInfo = '';
    if (this.username) {
      userInfo += encodeURIComponent(this.username);
      if (this.password) {
        userInfo += `:${encodeURIComponent(this.password)}`;
      }
      userInfo += '@';
    }
    let link = `${protocol}://${userInfo}${this.serverAddress}:${this.serverPort}`;
    if (this.name) {
      link += `#${encodeURIComponent(this.name)}`;
    }
    return link;
  }
}

/**
 * Hysteria Bean 类
 */
class HysteriaBean extends AbstractBean {
  constructor() {
    super();
    this.protocolVersion = 2;
    this.serverPorts = "443";
    this.authPayload = "";
    this.obfuscation = "";
    this.sni = "";
    this.uploadMbps = 0;
    this.downloadMbps = 0;
    this.allowInsecure = false;
    this.alpn = "";
    this.protocol = 0; // 0: UDP, 1: FAKETCP, 2: WECHAT_VIDEO
    this.authPayloadType = 1; // 1: String, 2: Base64
    this.caText = "";
    this.streamReceiveWindow = 0;
    this.connectionReceiveWindow = 0;
    this.disableMtuDiscovery = false;
    this.hopInterval = 10;
  }

  /**
   * 初始化默认值
   */
  initializeDefaultValues() {
    super.initializeDefaultValues();
    if (this.protocolVersion == null) this.protocolVersion = 2;
    if (!this.serverPorts) this.serverPorts = "443";
    if (!this.authPayload) this.authPayload = "";
    if (!this.obfuscation) this.obfuscation = "";
    if (!this.sni) this.sni = "";
    if (this.allowInsecure == null) this.allowInsecure = false;
    if (this.protocolVersion === 1) {
      if (this.uploadMbps == null) this.uploadMbps = 10;
      if (this.downloadMbps == null) this.downloadMbps = 50;
      if (!this.alpn) this.alpn = "";
    } else {
      if (this.uploadMbps == null) this.uploadMbps = 0;
      if (this.downloadMbps == null) this.downloadMbps = 0;
    }
    if (this.protocol == null) this.protocol = 0;
    if (this.authPayloadType == null) this.authPayloadType = 1;
    if (!this.caText) this.caText = "";
    if (this.streamReceiveWindow == null) this.streamReceiveWindow = 0;
    if (this.connectionReceiveWindow == null) this.connectionReceiveWindow = 0;
    if (this.disableMtuDiscovery == null) this.disableMtuDiscovery = false;
    if (this.hopInterval == null) this.hopInterval = 10;
  }

  /**
   * 转换为 URI
   * @returns {string} URI 字符串
   */
  toUri() {
    const protocol = this.protocolVersion === 2 ? 'hy2' : 'hysteria';
    const port = this.serverPorts.split(',')[0].split('-')[0];
    let userInfo = '';
    if (this.protocolVersion === 2 && this.authPayload) {
      userInfo = `${encodeURIComponent(this.authPayload)}@`;
    }
    let link = `${protocol}://${userInfo}${this.serverAddress}:${port}`;
    const params = new URLSearchParams();

    if (this.sni) {
      params.set(this.protocolVersion === 1 ? 'peer' : 'sni', this.sni);
    }
    if (this.allowInsecure) params.set('insecure', '1');

    if (this.protocolVersion === 1) {
      if (this.authPayload) params.set('auth', this.authPayload);
      params.set('upmbps', this.uploadMbps);
      params.set('downmbps', this.downloadMbps);
      if (this.alpn) params.set('alpn', this.alpn);
      if (this.obfuscation) params.set('obfsParam', this.obfuscation);
      const p = {
        1: 'faketcp',
        2: 'wechat-video'
      }[this.protocol];
      if (p) params.set('protocol', p);
    } else {
      if (this.obfuscation) {
        params.set('obfs-password', this.obfuscation);
      }
    }

    const queryString = params.toString();
    if (queryString) {
      link += `?${queryString}`;
    }
    if (this.name) {
      link += `#${encodeURIComponent(this.name)}`;
    }
    return link;
  }
}

/**
 * Tuic Bean 类
 */
class TuicBean extends AbstractBean {
  constructor() {
    super();
    this.protocolVersion = 5;
    this.uuid = "";
    this.token = "";
    this.sni = "";
    this.congestionController = "cubic";
    this.udpRelayMode = "native";
    this.alpn = "";
    this.allowInsecure = false;
    this.disableSNI = false;
    this.reduceRTT = false;
    this.caText = "";
    this.mtu = 1400;
  }

  /**
   * 初始化默认值
   */
  initializeDefaultValues() {
    super.initializeDefaultValues();
    if (this.protocolVersion == null) this.protocolVersion = 5;
    if (!this.uuid) this.uuid = "";
    if (!this.token) this.token = "";
    if (!this.sni) this.sni = "";
    if (!this.congestionController) this.congestionController = "cubic";
    if (!this.udpRelayMode) this.udpRelayMode = "native";
    if (!this.alpn) this.alpn = "";
    if (this.allowInsecure == null) this.allowInsecure = false;
    if (this.disableSNI == null) this.disableSNI = false;
    if (this.reduceRTT == null) this.reduceRTT = false;
    if (!this.caText) this.caText = "";
    if (this.mtu == null) this.mtu = 1400;
  }

  /**
   * 转换为 URI
   * @returns {string} URI 字符串
   */
  toUri() {
    let link = `tuic://${encodeURIComponent(this.uuid)}:${encodeURIComponent(this.token)}@${this.serverAddress}:${this.serverPort}`;
    const params = new URLSearchParams();
    if (this.sni) params.set('sni', this.sni);
    if (this.congestionController !== 'cubic') params.set('congestion_control', this.congestionController);
    if (this.udpRelayMode !== 'native') params.set('udp_relay_mode', this.udpRelayMode);
    if (this.alpn) params.set('alpn', this.alpn);
    if (this.allowInsecure) params.set('allow_insecure', '1');
    if (this.disableSNI) params.set('disable_sni', '1');
    if (this.reduceRTT) params.set('reduce_rtt', '1');

    const queryString = params.toString();
    if (queryString) {
      link += `?${queryString}`;
    }
    if (this.name) {
      link += `#${encodeURIComponent(this.name)}`;
    }
    return link;
  }
}

/**
 * WireGuard Bean 类
 */
class WireGuardBean extends AbstractBean {
  constructor() {
    super();
    this.localAddress = "";
    this.privateKey = "";
    this.peerPublicKey = "";
    this.peerPreSharedKey = "";
    this.mtu = 1420;
    this.reserved = "";
  }

  /**
   * 初始化默认值
   */
  initializeDefaultValues() {
    super.initializeDefaultValues();
    if (!this.localAddress) this.localAddress = "";
    if (!this.privateKey) this.privateKey = "";
    if (!this.peerPublicKey) this.peerPublicKey = "";
    if (!this.peerPreSharedKey) this.peerPreSharedKey = "";
    if (this.mtu == null) this.mtu = 1420;
    if (!this.reserved) this.reserved = "";
  }

  /**
   * 转换为 URI
   * @returns {string} URI 字符串
   */
  toUri() {
    let link = `wg://${encodeURIComponent(this.privateKey)}@${this.serverAddress}:${this.serverPort}`;
    const params = new URLSearchParams();
    params.set('public_key', this.peerPublicKey);
    if (this.peerPreSharedKey) params.set('preshared_key', this.peerPreSharedKey);
    if (this.localAddress) params.set('address', this.localAddress.split(',')[0]);
    if (this.reserved) params.set('reserved', this.reserved);
    if (this.mtu !== 1420) params.set('mtu', this.mtu);
    const queryString = params.toString();
    if (queryString) {
      link += `?${queryString}`;
    }
    if (this.name) {
      link += `#${encodeURIComponent(this.name)}`;
    }
    return link;
  }
}

/**
 * SSH Bean 类
 */
class SSHBean extends AbstractBean {
  constructor() {
    super();
    this.username = "root";
    this.password = "";
    this.authType = "password"; // "password" or "private_key"
    this.privateKey = "";
    this.privateKeyPassphrase = "";
    this.publicKey = "";
  }

  /**
   * 初始化默认值
   */
  initializeDefaultValues() {
    if (this.serverPort == null || this.serverPort === 1080) this.serverPort = 22;
    super.initializeDefaultValues();
    if (!this.username) this.username = "root";
    if (!this.password) this.password = "";
    if (!this.authType) this.authType = "password";
    if (!this.privateKey) this.privateKey = "";
    if (!this.privateKeyPassphrase) this.privateKeyPassphrase = "";
    if (!this.publicKey) this.publicKey = "";
  }

  /**
   * 转换为 URI
   * @returns {string} URI 字符串
   */
  toUri() {
    let userInfo = encodeURIComponent(this.username);
    if (this.authType === 'password' && this.password) {
      userInfo += `:${encodeURIComponent(this.password)}`;
    }
    let link = `ssh://${userInfo}@${this.serverAddress}:${this.serverPort}`;
    const params = new URLSearchParams();
    if (this.authType === 'private_key') {
      params.set('private_key', this.privateKey);
      if (this.privateKeyPassphrase) {
        params.set('passphrase', this.privateKeyPassphrase);
      }
    }
    if (this.publicKey) {
      params.set('host_key', this.publicKey);
    }

    const queryString = params.toString();
    if (queryString) {
      link += `?${queryString}`;
    }
    if (this.name) {
      link += `#${encodeURIComponent(this.name)}`;
    }
    return link;
  }
}

/**
 * AnyTLS Bean 类
 *
 * 基于 TLS 的密码认证代理协议(sing-box >= 1.12 原生支持).
 * 典型 URI 形式:
 *   anytls://<password>@<host>:<port>?sni=&insecure=1&alpn=&fp=...#<name>
 */
class AnyTLSBean extends AbstractBean {
  constructor() {
    super();
    this.password = "";
    this.sni = "";
    this.alpn = "";
    this.allowInsecure = false;
    this.utlsFingerprint = "";
    this.certificates = "";
    this.enableECH = false;
    this.echConfig = "";
    this.idleSessionCheckInterval = "";
    this.idleSessionTimeout = "";
    this.minIdleSession = 0;
  }

  /**
   * 初始化默认值
   */
  initializeDefaultValues() {
    if (this.serverPort == null || this.serverPort === 1080) this.serverPort = 443;
    super.initializeDefaultValues();
    if (!this.password) this.password = "";
    if (!this.sni) this.sni = "";
    if (!this.alpn) this.alpn = "";
    if (this.allowInsecure == null) this.allowInsecure = false;
    if (!this.utlsFingerprint) this.utlsFingerprint = "";
    if (!this.certificates) this.certificates = "";
    if (this.enableECH == null) this.enableECH = false;
    if (!this.echConfig) this.echConfig = "";
    if (!this.idleSessionCheckInterval) this.idleSessionCheckInterval = "";
    if (!this.idleSessionTimeout) this.idleSessionTimeout = "";
    if (this.minIdleSession == null) this.minIdleSession = 0;
  }

  /**
   * 转换为 URI
   * @returns {string} URI 字符串
   */
  toUri() {
    let link = `anytls://${encodeURIComponent(this.password)}@${this.serverAddress}:${this.serverPort}`;
    const params = new URLSearchParams();
    if (this.sni) params.set('sni', this.sni);
    if (this.alpn) params.set('alpn', this.alpn);
    if (this.allowInsecure) params.set('insecure', '1');
    if (this.utlsFingerprint) params.set('fp', this.utlsFingerprint);
    if (this.idleSessionCheckInterval) params.set('idle-session-check-interval', this.idleSessionCheckInterval);
    if (this.idleSessionTimeout) params.set('idle-session-timeout', this.idleSessionTimeout);
    if (this.minIdleSession > 0) params.set('min-idle-session', String(this.minIdleSession));
    const queryString = params.toString();
    if (queryString) link += `?${queryString}`;
    if (this.name) link += `#${encodeURIComponent(this.name)}`;
    return link;
  }
}

// --- 链接解析函数 ---

/**
 * 解析 V2Ray N 格式链接
 * @param {string} link - 链接
 * @returns {VMessBean} Bean 对象
 */
function parseV2RayN(link) {
  const data = b64Decode(link.substring("vmess://".length));
  const vmessQRCode = JSON.parse(data);
  const bean = new VMessBean();

  bean.name = vmessQRCode.ps || "";
  bean.serverAddress = vmessQRCode.add || "";
  bean.serverPort = parseInt(vmessQRCode.port, 10) || 443;
  bean.uuid = vmessQRCode.id || "";
  bean.alterId = parseInt(vmessQRCode.aid, 10) || 0;
  bean.encryption = vmessQRCode.scy || "auto";
  bean.type = vmessQRCode.net || "tcp";
  bean.host = vmessQRCode.host || "";
  bean.path = vmessQRCode.path || "";
  if (vmessQRCode.tls === "tls" || vmessQRCode.tls === "reality") {
    bean.security = vmessQRCode.tls === "reality" ? "reality" : "tls";
    bean.sni = vmessQRCode.sni || bean.host;
    bean.alpn = vmessQRCode.alpn || "";
    bean.utlsFingerprint = vmessQRCode.fp || "";
  }
  return bean;
}

/**
 * 解析 DuckSoft 格式链接
 * @param {URL} url - URL 对象
 * @param {StandardV2RayBean} bean - Bean 对象
 * @returns {StandardV2RayBean} Bean 对象
 */
function parseDuckSoft(url, bean) {
  bean.serverAddress = url.hostname;
  bean.serverPort = parseInt(url.port, 10) || (url.protocol === 'https:' ? 443 : 80);
  bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : "";

  if (bean instanceof TrojanBean) {
    bean.password = decodeURIComponent(url.username);
  } else {
    bean.uuid = decodeURIComponent(url.username);
  }

  bean.type = url.searchParams.get("type") || "tcp";
  bean.security = url.searchParams.get("security") || (bean instanceof TrojanBean ? "tls" : "none");
  if (bean.security === "tls" || bean.security === "reality") {
    bean.allowInsecure = url.searchParams.get("allowInsecure") === "1" || url.searchParams.get("allowInsecure") === "true";
    bean.sni = url.searchParams.get("sni") || url.searchParams.get("peer") || url.searchParams.get("host") || "";
    bean.alpn = url.searchParams.get("alpn") || "";
    bean.utlsFingerprint = url.searchParams.get("fp") || "";
    if (bean.security === "reality" || url.searchParams.get("pbk")) {
      bean.security = "reality";
      bean.realityPubKey = url.searchParams.get("pbk") || "";
      bean.realityShortId = url.searchParams.get("sid") || "";
    }
  }

  switch (bean.type) {
    case "ws":
      bean.host = url.searchParams.get("host") || "";
      bean.path = url.searchParams.get("path") || "/";
      break;
    case "http":
      bean.host = url.searchParams.get("host") || "";
      bean.path = url.searchParams.get("path") || "/";
      break;
    case "grpc":
      bean.path = url.searchParams.get("serviceName") || "";
      break;
  }

  if (bean instanceof VMessBean && bean.isVLESS()) {
    bean.encryption = url.searchParams.get("flow") || "";
  }

  return bean;
}

/**
 * 解析 V2Ray 链接
 * @param {string} link - 链接
 * @returns {StandardV2RayBean} Bean 对象
 */
function parseV2Ray(link) {
  const protocol = link.split('://')[0];
  if (protocol === 'vmess' && !link.includes('@')) {
    try {
      return parseV2RayN(link);
    } catch (e) {
      // ignore and fallback
    }
  }

  const bean = protocol === 'trojan' ? new TrojanBean() : new VMessBean();
  if (protocol === 'vless') {
    bean.alterId = -1;
  }

  const urlString = link.replace(`${protocol}://`, 'https://');
  const url = new URL(urlString);

  return parseDuckSoft(url, bean);
}

/**
 * 解析 Shadowsocks 链接
 * @param {string} link - 链接
 * @returns {ShadowsocksBean} Bean 对象
 */
function parseShadowsocks(link) {
  const bean = new ShadowsocksBean();
  const hashIndex = link.indexOf('#');
  const uriPart = hashIndex === -1 ? link.substring(5) : link.substring(5, hashIndex);
  bean.name = hashIndex === -1 ? '' : decodeURIComponent(link.substring(hashIndex + 1));

  if (!uriPart.includes('@')) {
    const decoded = b64Decode(uriPart);
    const atIndex = decoded.indexOf('@');
    if (atIndex === -1) throw new Error("Invalid Base64-encoded SS format");

    const credsPart = decoded.substring(0, atIndex);
    const serverPart = decoded.substring(atIndex + 1);

    const [method, password] = credsPart.split(':');
    const [serverAddress, serverPortStr] = serverPart.split(':');

    bean.method = method;
    bean.password = password;
    bean.serverAddress = serverAddress;
    bean.serverPort = parseInt(serverPortStr, 10) || 443;
  } else {
    const url = new URL(`https://${uriPart}`);
    bean.serverAddress = url.hostname;
    bean.serverPort = parseInt(url.port, 10) || 443;
    bean.plugin = url.searchParams.get('plugin') || '';
    if (url.password) {
      bean.method = decodeURIComponent(url.username);
      bean.password = decodeURIComponent(url.password);
    } else {
      try {
        const decoded = b64Decode(decodeURIComponent(url.username));
        const [method, password] = decoded.split(':');
        bean.method = method;
        bean.password = password;
      } catch (e) {
        throw new Error("Invalid Shadowsocks credentials format");
      }
    }
  }

  if (bean.plugin.startsWith("simple-obfs")) {
    bean.plugin = bean.plugin.replace("simple-obfs", "obfs-local");
  }

  return bean;
}

/**
 * 解析 Socks 链接
 * @param {string} link - 链接
 * @returns {SocksBean} Bean 对象
 */
function parseSocks(link) {
  const bean = new SocksBean();
  const protocol = link.split('://')[0];

  switch (protocol) {
    case 'socks4':
      bean.protocol = 0;
      break;
    case 'socks4a':
      bean.protocol = 1;
      break;
    default:
      bean.protocol = 2;
      break;
  }

  const url = new URL(link.replace(protocol, 'http'));
  bean.serverAddress = url.hostname;
  bean.serverPort = parseInt(url.port, 10) || 1080;
  bean.username = decodeURIComponent(url.username);
  bean.password = decodeURIComponent(url.password);
  bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : '';

  if (!bean.password && bean.username) {
    try {
      const decoded = b64Decode(bean.username);
      if (decoded.includes(':')) {
        [bean.username, bean.password] = decoded.split(':', 2);
      }
    } catch (e) {
      // Ignore error if it's not Base64
    }
  }

  return bean;
}

/**
 * 解析 HTTP 链接
 * @param {string} link - 链接
 * @returns {HttpBean} Bean 对象
 */
function parseHttp(link) {
  const bean = new HttpBean();
  const url = new URL(link);
  bean.security = url.protocol === 'https:' ? 'tls' : 'none';
  bean.serverAddress = url.hostname;
  bean.serverPort = parseInt(url.port, 10) || (bean.isTLS() ? 443 : 80);
  bean.username = decodeURIComponent(url.username);
  bean.password = decodeURIComponent(url.password);
  bean.sni = url.searchParams.get('sni') || '';
  bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : '';

  return bean;
}

/**
 * 解析 Hysteria1 链接
 * @param {URL} url - URL 对象
 * @returns {HysteriaBean} Bean 对象
 */
function parseHysteria1(url) {
  const bean = new HysteriaBean();
  bean.protocolVersion = 1;
  bean.serverAddress = url.hostname;
  bean.serverPorts = url.port || "443";
  bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : '';

  bean.serverPorts = url.searchParams.get("mport") || bean.serverPorts;
  bean.sni = url.searchParams.get("peer") || "";
  bean.authPayload = url.searchParams.get("auth") || "";
  if (bean.authPayload) bean.authPayloadType = 1;
  bean.allowInsecure = url.searchParams.get("insecure") === "1";
  bean.uploadMbps = safeParseInt(url.searchParams.get("upmbps"), 10);
  bean.downloadMbps = safeParseInt(url.searchParams.get("downmbps"), 50);
  bean.alpn = url.searchParams.get("alpn") || "";
  bean.obfuscation = url.searchParams.get("obfsParam") || "";

  const protocolStr = url.searchParams.get("protocol");
  if (protocolStr === "faketcp") bean.protocol = 1;
  if (protocolStr === "wechat-video") bean.protocol = 2;

  return bean;
}

/**
 * 解析 Hysteria2 链接
 * @param {URL} url - URL 对象
 * @returns {HysteriaBean} Bean 对象
 */
function parseHysteria2(url) {
  const bean = new HysteriaBean();
  bean.protocolVersion = 2;
  bean.serverAddress = url.hostname;
  bean.serverPorts = url.port || "443";
  bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : '';
  if (url.username) {
    bean.authPayload = decodeURIComponent(url.username);
    if (url.password) {
      bean.authPayload += `:${decodeURIComponent(url.password)}`;
    }
  }

  bean.serverPorts = url.searchParams.get("mport") || bean.serverPorts;
  bean.sni = url.searchParams.get("sni") || "";
  bean.allowInsecure = url.searchParams.get("insecure") === "1";
  bean.obfuscation = url.searchParams.get("obfs-password") || "";
  return bean;
}

/**
 * 解析 Hysteria 链接
 * @param {string} link - 链接
 * @returns {HysteriaBean} Bean 对象
 */
function parseHysteria(link) {
  const protocol = link.split('://')[0].toLowerCase();
  const urlString = link.replace(protocol + '://', 'https://');
  const url = new URL(urlString);

  if (protocol === 'hysteria') {
    return parseHysteria1(url);
  } else {
    return parseHysteria2(url);
  }
}

/**
 * 解析 Tuic 链接
 * @param {string} link - 链接
 * @returns {TuicBean} Bean 对象
 */
function parseTuic(link) {
  const bean = new TuicBean();
  const url = new URL(link.replace('tuic://', 'https://'));
  bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : '';
  bean.uuid = decodeURIComponent(url.username);
  bean.token = decodeURIComponent(url.password);
  bean.serverAddress = url.hostname;
  bean.serverPort = parseInt(url.port, 10) || 443;
  bean.sni = url.searchParams.get('sni') || '';
  bean.congestionController = url.searchParams.get('congestion_control') || 'cubic';
  bean.udpRelayMode = url.searchParams.get('udp_relay_mode') || 'native';
  bean.alpn = url.searchParams.get('alpn') || '';
  bean.allowInsecure = url.searchParams.get('allow_insecure') === '1';
  bean.disableSNI = url.searchParams.get('disable_sni') === '1';
  bean.reduceRTT = url.searchParams.get('reduce_rtt') === '1';

  return bean;
}

/**
 * 解析 WireGuard 链接
 * @param {string} link - 链接
 * @returns {WireGuardBean} Bean 对象
 */
function parseWireGuard(link) {
  const bean = new WireGuardBean();
  const url = new URL(link.replace('wg://', 'http://'));
  bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : '';
  bean.privateKey = decodeURIComponent(url.username);
  bean.serverAddress = url.hostname;
  bean.serverPort = parseInt(url.port, 10) || 51820;
  bean.peerPublicKey = url.searchParams.get('public_key') || url.searchParams.get('peer_public_key') || '';
  bean.peerPreSharedKey = url.searchParams.get('preshared_key') || '';
  bean.localAddress = url.searchParams.get('address') || '';
  const mtu = url.searchParams.get('mtu');
  if (mtu) bean.mtu = parseInt(mtu, 10);
  bean.reserved = url.searchParams.get('reserved') || '';

  return bean;
}

/**
 * 解析 SSH 链接
 * @param {string} link - 链接
 * @returns {SSHBean} Bean 对象
 */
function parseSSH(link) {
  const bean = new SSHBean();
  const url = new URL(link.replace('ssh://', 'http://'));

  bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : '';
  bean.serverAddress = url.hostname;
  bean.serverPort = parseInt(url.port, 10) || 22;
  bean.username = decodeURIComponent(url.username);
  bean.password = decodeURIComponent(url.password) || url.searchParams.get('password') || '';

  bean.privateKey = url.searchParams.get('private_key') || '';
  bean.privateKeyPassphrase = url.searchParams.get('passphrase') || '';
  bean.publicKey = url.searchParams.get('host_key') || '';
  if (bean.privateKey) {
    bean.authType = 'private_key';
  } else {
    bean.authType = 'password';
  }

  return bean;
}

/**
 * 解析 AnyTLS 链接
 *
 * 兼容:
 *   - userinfo 形式: anytls://pwd@host:port
 *   - user:pass 形式: anytls://user:pass@host:port (合并为 user:pass 作为 password)
 *   - 查询参数下划线或连字符混用
 *
 * @param {string} link - 链接
 * @returns {AnyTLSBean} Bean 对象
 */
function parseAnyTLS(link) {
  const bean = new AnyTLSBean();
  const url = new URL(link.replace('anytls://', 'https://'));

  bean.name = url.hash ? decodeURIComponent(url.hash.substring(1)) : '';
  bean.serverAddress = url.hostname;
  bean.serverPort = parseInt(url.port, 10) || 443;

  if (url.password) {
    bean.password = `${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`;
  } else {
    bean.password = decodeURIComponent(url.username);
  }

  const getParam = (...keys) => {
    for (const k of keys) {
      const v = url.searchParams.get(k);
      if (v != null && v !== '') return v;
    }
    return '';
  };
  const getBoolParam = (...keys) => {
    const v = getParam(...keys);
    return v === '1' || v.toLowerCase() === 'true';
  };

  bean.sni = getParam('sni', 'peer', 'host', 'servername');
  bean.alpn = getParam('alpn');
  bean.allowInsecure = getBoolParam('insecure', 'allow_insecure', 'allowInsecure', 'skip-cert-verify');
  bean.utlsFingerprint = getParam('fp', 'fingerprint', 'client-fingerprint');
  bean.certificates = getParam('ca', 'certificate');
  bean.idleSessionCheckInterval = getParam('idle-session-check-interval', 'idle_session_check_interval');
  bean.idleSessionTimeout = getParam('idle-session-timeout', 'idle_session_timeout');
  bean.minIdleSession = safeParseInt(getParam('min-idle-session', 'min_idle_session'), 0);

  const echConfig = getParam('ech-config', 'ech_config');
  if (echConfig) {
    bean.enableECH = true;
    bean.echConfig = echConfig;
  }

  return bean;
}

/**
 * 解析链接主函数
 * @param {string} link - 链接
 * @returns {AbstractBean|null} Bean 对象或 null
 */
function parseLink(link) {
  if (!link || typeof link !== 'string') return null;

  const protocol = link.split('://')[0].toLowerCase();
  let bean = null;

  try {
    switch (protocol) {
      case 'vmess':
      case 'vless':
      case 'trojan':
        bean = parseV2Ray(link);
        break;
      case 'ss':
        bean = parseShadowsocks(link);
        break;
      case 'socks':
      case 'socks4':
      case 'socks4a':
      case 'socks5':
        bean = parseSocks(link);
        break;
      case 'http':
      case 'https':
        bean = parseHttp(link);
        break;
      case 'hysteria':
      case 'hy2':
      case 'hysteria2':
        bean = parseHysteria(link);
        break;
      case 'tuic':
        bean = parseTuic(link);
        break;
      case 'wg':
        bean = parseWireGuard(link);
        break;
      case 'ssh':
        bean = parseSSH(link);
        break;
      case 'anytls':
        bean = parseAnyTLS(link);
        break;
      default:
        return null;
    }
  } catch (e) {
    console.warn(`[!] Failed to parse link "${link}": ${e.message}`);
    return null;
  }

  return bean;
}

/**
 * Bean 后处理函数
 * @param {AbstractBean} bean - Bean 对象
 * @param {object} options - 选项
 * @returns {AbstractBean} 处理后的 Bean 对象
 */
function postProcessBean(bean, options = {}) {
  bean.initializeDefaultValues();

  if (bean instanceof StandardV2RayBean) {
    if (bean.isTLS() && !bean.sni && bean.host && !isIpAddress(bean.host)) {
      bean.sni = bean.host;
    }
  }

  if (bean instanceof AnyTLSBean) {
    if (!bean.sni && bean.serverAddress && !isIpAddress(bean.serverAddress)) {
      bean.sni = bean.serverAddress;
    }
  }

  return bean;
}

// --- Sing-box Outbound 构建函数 ---

/**
 * 构建 Sing-box MUX 设置
 * @param {AbstractBean} bean - Bean 对象
 * @returns {object|undefined} MUX 设置
 */
function buildSingboxMux(bean) {
  if (!bean.enableMux) return undefined;
  return {
    enabled: true,
    protocol: bean.muxType === 1 ? 'h2mux' : 'smux',
    max_streams: bean.muxConcurrency,
    padding: bean.muxPadding,
  };
}

/**
 * 构建 Sing-box TLS 设置
 * @param {AbstractBean} bean - Bean 对象
 * @param {boolean} globalAllowInsecure - 全局允许不安全连接
 * @returns {object|undefined} TLS 设置
 */
function buildSingboxTLS(bean, globalAllowInsecure = false) {
  if (!bean.isTLS()) return undefined;
  const tls = {
    enabled: true,
    insecure: bean.allowInsecure || globalAllowInsecure,
  };

  if (bean.sni) tls.server_name = bean.sni;
  if (bean.alpn) tls.alpn = listByLineOrComma(bean.alpn);
  if (bean.certificates) tls.certificate = bean.certificates;
  let fp = bean.utlsFingerprint;

  if (bean.security === 'reality') {
    tls.reality = {
      enabled: true,
      public_key: bean.realityPubKey,
      short_id: bean.realityShortId,
    };
    if (!fp) fp = "chrome";
  }

  if (fp) {
    tls.utls = {
      enabled: true,
      fingerprint: fp,
    };
  }

  if (bean.enableECH && bean.echConfig) {
    tls.ech = {
      enabled: true,
      config: listByLineOrComma(bean.echConfig),
    };
  }

  return tls;
}

/**
 * 构建 Sing-box 流设置
 * @param {AbstractBean} bean - Bean 对象
 * @returns {object|undefined} 流设置
 */
function buildSingboxStreamSettings(bean) {
  switch (bean.type) {
    case "tcp":
      return undefined;
    case "ws":
      const wsSettings = {
        type: "ws",
        headers: {},
      };
      if (bean.host) wsSettings.headers.Host = bean.host;

      if (bean.path && bean.path.includes("?ed=")) {
        wsSettings.path = bean.path.substring(0, bean.path.indexOf("?ed="));
        wsSettings.max_early_data = parseInt(bean.path.substring(bean.path.indexOf("?ed=") + 4), 10) || 2048;
        wsSettings.early_data_header_name = "Sec-WebSocket-Protocol";
      } else {
        wsSettings.path = bean.path || "/";
      }

      if (bean.wsMaxEarlyData > 0) {
        wsSettings.max_early_data = bean.wsMaxEarlyData;
      }
      if (bean.earlyDataHeaderName) {
        wsSettings.early_data_header_name = bean.earlyDataHeaderName;
      }
      return wsSettings;
    case "http":
      const httpSettings = {
        type: "http",
        path: bean.path || "/",
      };
      if (bean.host) {
        httpSettings.host = listByLineOrComma(bean.host);
      }
      if (!bean.isTLS()) {
        httpSettings.method = "GET";
      }
      return httpSettings;
    case "grpc":
      return {
        type: "grpc",
        service_name: bean.path,
      };
    case "quic":
      return {
        type: "quic",
      };
    case "httpupgrade":
      return {
        type: "httpupgrade",
        host: bean.host,
        path: bean.path,
      };
    default:
      return undefined;
  }
}

/**
 * 构建 Sing-box VMess Outbound
 * @param {VMessBean} bean - Bean 对象
 * @param {object} options - 选项
 * @returns {object} Outbound 对象
 */
function buildSingboxVMess(bean, options) {
  const base = {
    tag: bean.displayName(),
    server: bean.serverAddress,
    server_port: bean.serverPort,
    uuid: bean.uuid,
    multiplex: buildSingboxMux(bean),
    tls: buildSingboxTLS(bean, options.globalAllowInsecure),
    transport: buildSingboxStreamSettings(bean),
  };

  let packetEncodingStr = "";
  if (bean.packetEncoding === 1) packetEncodingStr = "packetaddr";
  if (bean.packetEncoding === 2) packetEncodingStr = "xudp";

  if (bean.isVLESS()) {
    const vlessOutbound = {
      ...base,
      type: 'vless',
      packet_encoding: packetEncodingStr || undefined,
    };
    if (bean.encryption && bean.encryption !== "auto") {
      vlessOutbound.flow = bean.encryption;
    }
    return vlessOutbound;
  } else {
    return {
      ...base,
      type: 'vmess',
      alter_id: bean.alterId,
      security: bean.encryption || 'auto',
      packet_encoding: packetEncodingStr || undefined,
    };
  }
}

/**
 * 构建 Sing-box Trojan Outbound
 * @param {TrojanBean} bean - Bean 对象
 * @param {object} options - 选项
 * @returns {object} Outbound 对象
 */
function buildSingboxTrojan(bean, options) {
  return {
    tag: bean.displayName(),
    type: 'trojan',
    server: bean.serverAddress,
    server_port: bean.serverPort,
    password: bean.password,
    multiplex: buildSingboxMux(bean),
    tls: buildSingboxTLS(bean, options.globalAllowInsecure),
    transport: buildSingboxStreamSettings(bean),
  };
}

/**
 * 构建 Sing-box Shadowsocks Outbound
 * @param {ShadowsocksBean} bean - Bean 对象
 * @returns {object} Outbound 对象
 */
function buildSingboxShadowsocks(bean) {
  const outbound = {
    tag: bean.displayName(),
    type: 'shadowsocks',
    server: bean.serverAddress,
    server_port: bean.serverPort,
    method: bean.method,
    password: bean.password,
  };
  if (bean.plugin) {
    const parts = bean.plugin.split(';');
    outbound.plugin = parts[0];
    outbound.plugin_opts = parts.slice(1).join(';');
  }
  if (bean.sUoT) {
    outbound.udp_over_tcp = true;
  }
  return outbound;
}

/**
 * 构建 Sing-box Socks Outbound
 * @param {SocksBean} bean - Bean 对象
 * @returns {object} Outbound 对象
 */
function buildSingboxSocks(bean) {
  const outbound = {
    tag: bean.displayName(),
    type: 'socks',
    server: bean.serverAddress,
    server_port: bean.serverPort,
    version: bean.protocolVersionName(),
    username: bean.username || undefined,
    password: bean.password || undefined,
  };
  if (bean.sUoT) {
    outbound.udp_over_tcp = true;
  }
  return outbound;
}

/**
 * 构建 Sing-box HTTP Outbound
 * @param {HttpBean} bean - Bean 对象
 * @param {object} options - 选项
 * @returns {object} Outbound 对象
 */
function buildSingboxHttp(bean, options) {
  return {
    tag: bean.displayName(),
    type: 'http',
    server: bean.serverAddress,
    server_port: bean.serverPort,
    username: bean.username || undefined,
    password: bean.password || undefined,
    tls: buildSingboxTLS(bean, options.globalAllowInsecure),
  };
}

/**
 * 构建 Sing-box Hysteria Outbound
 * @param {HysteriaBean} bean - Bean 对象
 * @param {object} options - 选项
 * @returns {object} Outbound 对象
 */
function buildSingboxHysteria(bean, options) {
  const tls = {
    enabled: true,

    insecure: bean.allowInsecure || options.globalAllowInsecure,
    server_name: bean.sni || undefined,
    certificate: bean.caText || undefined,
  };

  if (bean.protocolVersion === 1) {
    if (bean.alpn) tls.alpn = listByLineOrComma(bean.alpn);
    const outbound = {
      tag: bean.displayName(),
      type: 'hysteria',
      server: bean.serverAddress,
      up_mbps: bean.uploadMbps,
      down_mbps: bean.downloadMbps,
      obfs: bean.obfuscation || undefined,
      auth_str: bean.authPayloadType === 1 ? bean.authPayload : undefined,
      auth: bean.authPayloadType === 2 ? bean.authPayload : undefined,
      hop_interval: `${bean.hopInterval}s`,
      disable_path_mtu_discovery: bean.disableMtuDiscovery,
      tls: tls,
    };
    if (isMultiPort(bean.serverPorts)) {
      outbound.server_ports = hopPortsToSingboxList(bean.serverPorts);
    } else {
      outbound.server_port = safeParseInt(bean.serverPorts);
    }
    if (bean.streamReceiveWindow > 0) {
      outbound.stream_receive_window = `${bean.streamReceiveWindow} B`;
    }
    if (bean.connectionReceiveWindow > 0) {
      outbound.connection_receive_window = `${bean.connectionReceiveWindow} B`;
    }
    return outbound;
  } else {
    tls.alpn = ['h3'];
    const obfs = bean.obfuscation ? {
      type: 'salamander',
      password: bean.obfuscation
    } : undefined;
    const outbound = {
      tag: bean.displayName(),
      type: 'hysteria2',
      server: bean.serverAddress,
      up_mbps: bean.uploadMbps,
      down_mbps: bean.downloadMbps,
      password: bean.authPayload,
      obfs: obfs,
      tls: tls,
    };
    if (isMultiPort(bean.serverPorts)) {
      outbound.server_ports = hopPortsToSingboxList(bean.serverPorts);
    } else {
      outbound.server_port = safeParseInt(bean.serverPorts);
    }
    return outbound;
  }
}

/**
 * 构建 Sing-box Tuic Outbound
 * @param {TuicBean} bean - Bean 对象
 * @param {object} options - 选项
 * @returns {object} Outbound 对象
 */
function buildSingboxTuic(bean, options) {
  const outbound = {
    tag: bean.displayName(),
    type: 'tuic',
    server: bean.serverAddress,
    server_port: bean.serverPort,
    uuid: bean.uuid,
    password: bean.token,
    congestion_control: bean.congestionController,
    zero_rtt_handshake: bean.reduceRTT,
    tls: {
      enabled: true,
      insecure: bean.allowInsecure || options.globalAllowInsecure,
      server_name: bean.sni || undefined,
      alpn: listByLineOrComma(bean.alpn),
      disable_sni: bean.disableSNI,
      certificate: bean.caText || undefined,
    }
  };
  if (bean.udpRelayMode === 'quic') {
    outbound.udp_relay_mode = 'quic';
  }
  return outbound;
}

/**
 * 构建 Sing-box WireGuard Outbound
 * @param {WireGuardBean} bean - Bean 对象
 * @returns {object} Outbound 对象
 */
function buildSingboxWireguard(bean) {
  const peer = {
    address: bean.serverAddress,
    port: bean.serverPort,
    public_key: bean.peerPublicKey,
    allowed_ips: ['0.0.0.0/0', '::/0'],
  };
  if (bean.peerPreSharedKey) {
    peer.pre_shared_key = bean.peerPreSharedKey;
  }
  if (bean.reserved) {
    peer.reserved = genWgReserved(bean.reserved);
  }

  return {
    tag: bean.displayName(),
    type: 'wireguard',
    address: listByLineOrComma(bean.localAddress),
    private_key: bean.privateKey,
    mtu: bean.mtu,
    peers: [peer],
  };
}

/**
 * 构建 Sing-box SSH Outbound
 * @param {SSHBean} bean - Bean 对象
 * @returns {object} Outbound 对象
 */
function buildSingboxSSH(bean) {
  const outbound = {
    tag: bean.displayName(),
    type: 'ssh',
    server: bean.serverAddress,
    server_port: bean.serverPort,
    user: bean.username,
  };
  if (bean.publicKey) {
    outbound.host_key = listByLineOrComma(bean.publicKey);
  }
  if (bean.authType === 'private_key') {
    outbound.private_key = bean.privateKey;
    outbound.private_key_passphrase = bean.privateKeyPassphrase || undefined;
  } else {
    outbound.password = bean.password;
  }
  return outbound;
}

/**
 * 构建 Sing-box AnyTLS Outbound
 * @param {AnyTLSBean} bean - Bean 对象
 * @param {object} options - 选项
 * @returns {object} Outbound 对象
 */
function buildSingboxAnyTLS(bean, options) {
  const tls = {
    enabled: true,
    insecure: bean.allowInsecure || options.globalAllowInsecure,
  };
  if (bean.sni) tls.server_name = bean.sni;
  if (bean.alpn) tls.alpn = listByLineOrComma(bean.alpn);
  if (bean.certificates) tls.certificate = bean.certificates;
  if (bean.utlsFingerprint) {
    tls.utls = {
      enabled: true,
      fingerprint: bean.utlsFingerprint,
    };
  }
  if (bean.enableECH && bean.echConfig) {
    tls.ech = {
      enabled: true,
      config: listByLineOrComma(bean.echConfig),
    };
  }

  const outbound = {
    tag: bean.displayName(),
    type: 'anytls',
    server: bean.serverAddress,
    server_port: bean.serverPort,
    password: bean.password,
    tls: tls,
  };
  if (bean.idleSessionCheckInterval) {
    outbound.idle_session_check_interval = bean.idleSessionCheckInterval;
  }
  if (bean.idleSessionTimeout) {
    outbound.idle_session_timeout = bean.idleSessionTimeout;
  }
  if (bean.minIdleSession > 0) {
    outbound.min_idle_session = bean.minIdleSession;
  }
  return outbound;
}

/**
 * 构建 Sing-box Outbound 主函数
 * @param {AbstractBean} bean - Bean 对象
 * @param {object} options - 选项
 * @returns {object} Outbound 对象
 */
function buildSingboxOutbound(bean, options) {
  if (bean instanceof VMessBean) return buildSingboxVMess(bean, options);
  if (bean instanceof TrojanBean) return buildSingboxTrojan(bean, options);
  if (bean instanceof ShadowsocksBean) return buildSingboxShadowsocks(bean, options);
  if (bean instanceof SocksBean) return buildSingboxSocks(bean, options);
  if (bean instanceof HttpBean) return buildSingboxHttp(bean, options);
  if (bean instanceof HysteriaBean) return buildSingboxHysteria(bean, options);
  if (bean instanceof TuicBean) return buildSingboxTuic(bean, options);
  if (bean instanceof WireGuardBean) return buildSingboxWireguard(bean, options);
  if (bean instanceof SSHBean) return buildSingboxSSH(bean, options);
  if (bean instanceof AnyTLSBean) return buildSingboxAnyTLS(bean, options);
  throw new Error(`Unsupported bean type for Sing-box conversion: ${bean.constructor.name}`);
}

// --- 主要导出函数 ---

/**
 * 将输入转换为 Outbound 数组
 * @param {string} input - 输入字符串
 * @param {object} options - 选项
 * @returns {object[]|undefined} Outbound 数组
 */
async function convertToOutbounds(input, options = {}) {
  let beans = [];

  const lines = input.trim().split('\n');
  const isLikelyLinks = lines.every(line => line.trim().includes('://') || line.trim() === '');

  if (isLikelyLinks && !input.includes('proxies:') && !input.includes('[Interface]')) {
    const links = input.split(/[\n\s]+/).filter(Boolean);
    beans = links.map(parseLink).filter(Boolean);
  } else {
    beans = parseRawContent(input);
  }

  const outbounds = [];
  for (let bean of beans) {
    try {
      bean = postProcessBean(bean, options);
      const singboxOutbound = buildSingboxOutbound(bean, options);
      outbounds.push(singboxOutbound);
    } catch (e) {
      console.warn(`[!] Failed to build outbound for bean "${bean.displayName()}": ${e.message}`);
    }
  }

  if (options.outputPath) {
    const jsonString = JSON.stringify({
      outbounds
    }, null, options.pretty !== false ? 2 : 0);
    await fs.writeFile(options.outputPath, jsonString, 'utf-8');
    console.log(`✅ Sing-box configuration saved to ${options.outputPath}`);
    return;
  }

  return outbounds;
}

// --- 反向解析函数 (Outbound -> Bean) ---

/**
 * 解析 Sing-box TLS 设置
 * @param {object} outbound - Outbound 对象
 * @param {AbstractBean} bean - Bean 对象
 */
function parseSingboxTLS(outbound, bean) {
  if (!outbound.tls || !outbound.tls.enabled) return;

  bean.security = 'tls';
  bean.allowInsecure = outbound.tls.insecure || false;
  bean.sni = outbound.tls.server_name || '';
  bean.alpn = (outbound.tls.alpn || []).join(',');
  bean.certificates = outbound.tls.certificate || '';

  if (outbound.tls.utls && outbound.tls.utls.enabled) {
    bean.utlsFingerprint = outbound.tls.utls.fingerprint || '';
  }

  if (outbound.tls.reality && outbound.tls.reality.enabled) {
    bean.security = 'reality';
    bean.realityPubKey = outbound.tls.reality.public_key || '';
    bean.realityShortId = outbound.tls.reality.short_id || '';
  }
}

/**
 * 解析 Sing-box 传输设置
 * @param {object} outbound - Outbound 对象
 * @param {AbstractBean} bean - Bean 对象
 */
function parseSingboxTransport(outbound, bean) {
  if (!outbound.transport) return;
  bean.type = outbound.transport.type || 'tcp';

  switch (bean.type) {
    case 'ws':
      bean.path = outbound.transport.path || '/';
      bean.host = (outbound.transport.headers && outbound.transport.headers.Host) || '';
      break;
    case 'http':
      bean.path = outbound.transport.path || '/';
      bean.host = (Array.isArray(outbound.transport.host) ? outbound.transport.host.join(',') : outbound.transport.host) || '';
      break;
    case 'grpc':
      bean.path = outbound.transport.service_name || '';
      break;
  }
}

/**
 * 解析 Sing-box VMess Outbound
 * @param {object} outbound - Outbound 对象
 * @returns {VMessBean} Bean 对象
 */
function parseSingboxVMess(outbound) {
  const bean = new VMessBean();
  bean.name = outbound.tag;
  bean.serverAddress = outbound.server;
  bean.serverPort = outbound.server_port;
  bean.uuid = outbound.uuid;

  if (outbound.type === 'vless') {
    bean.alterId = -1;
    bean.encryption = outbound.flow || '';
  } else {
    bean.alterId = outbound.alter_id;
    bean.encryption = outbound.security || 'auto';
  }

  parseSingboxTLS(outbound, bean);
  parseSingboxTransport(outbound, bean);

  return bean;
}

/**
 * 解析 Sing-box Trojan Outbound
 * @param {object} outbound - Outbound 对象
 * @returns {TrojanBean} Bean 对象
 */
function parseSingboxTrojan(outbound) {
  const bean = new TrojanBean();
  bean.name = outbound.tag;
  bean.serverAddress = outbound.server;
  bean.serverPort = outbound.server_port;
  bean.password = outbound.password;

  parseSingboxTLS(outbound, bean);
  parseSingboxTransport(outbound, bean);

  return bean;
}

/**
 * 解析 Sing-box Shadowsocks Outbound
 * @param {object} outbound - Outbound 对象
 * @returns {ShadowsocksBean} Bean 对象
 */
function parseSingboxShadowsocks(outbound) {
  const bean = new ShadowsocksBean();
  bean.name = outbound.tag;
  bean.serverAddress = outbound.server;
  bean.serverPort = outbound.server_port;
  bean.method = outbound.method;
  bean.password = outbound.password;
  if (outbound.plugin) {
    bean.plugin = `${outbound.plugin};${outbound.plugin_opts || ''}`;
  }
  return bean;
}

/**
 * 解析 Sing-box Socks Outbound
 * @param {object} outbound - Outbound 对象
 * @returns {SocksBean} Bean 对象
 */
function parseSingboxSocks(outbound) {
  const bean = new SocksBean();
  bean.name = outbound.tag;
  bean.serverAddress = outbound.server;
  bean.serverPort = outbound.server_port;
  bean.username = outbound.username || '';
  bean.password = outbound.password || '';

  const versionMap = {
    '4': 0,
    '4a': 1,
    '5': 2
  };
  bean.protocol = versionMap[outbound.version] ?? 2;
  return bean;
}

/**
 * 解析 Sing-box HTTP Outbound
 * @param {object} outbound - Outbound 对象
 * @returns {HttpBean} Bean 对象
 */
function parseSingboxHttp(outbound) {
  const bean = new HttpBean();
  bean.name = outbound.tag;
  bean.serverAddress = outbound.server;
  bean.serverPort = outbound.server_port;
  bean.username = outbound.username || '';
  bean.password = outbound.password || '';

  if (outbound.tls && outbound.tls.enabled) {
    bean.security = 'tls';
    bean.sni = outbound.tls.server_name || '';
  } else {
    bean.security = 'none';
  }
  return bean;
}

/**
 * 解析 Sing-box Hysteria Outbound
 * @param {object} outbound - Outbound 对象
 * @returns {HysteriaBean} Bean 对象
 */
function parseSingboxHysteria(outbound) {
  const bean = new HysteriaBean();
  bean.name = outbound.tag;
  bean.serverAddress = outbound.server;
  bean.serverPorts = String(outbound.server_port);
  bean.uploadMbps = outbound.up_mbps || 0;
  bean.downloadMbps = outbound.down_mbps || 0;

  if (outbound.type === 'hysteria2') {
    bean.protocolVersion = 2;
    bean.authPayload = outbound.password || '';
    if (outbound.obfs) {
      bean.obfuscation = outbound.obfs.password || '';
    }
  } else {
    bean.protocolVersion = 1;
    bean.obfuscation = outbound.obfs || '';
    if (outbound.auth_str) {
      bean.authPayload = outbound.auth_str;
      bean.authPayloadType = 1;
    } else if (outbound.auth) {
      bean.authPayload = outbound.auth;
      bean.authPayloadType = 2;
    }
  }

  if (outbound.tls) {
    bean.allowInsecure = outbound.tls.insecure || false;
    bean.sni = outbound.tls.server_name || '';
    bean.alpn = (outbound.tls.alpn || []).join(',');
    bean.caText = outbound.tls.certificate || '';
  }
  return bean;
}

/**
 * 解析 Sing-box Tuic Outbound
 * @param {object} outbound - Outbound 对象
 * @returns {TuicBean} Bean 对象
 */
function parseSingboxTuic(outbound) {
  const bean = new TuicBean();
  bean.name = outbound.tag;
  bean.serverAddress = outbound.server;
  bean.serverPort = outbound.server_port;
  bean.uuid = outbound.uuid;
  bean.token = outbound.password;
  bean.congestionController = outbound.congestion_control || 'cubic';
  bean.udpRelayMode = outbound.udp_relay_mode || 'native';

  if (outbound.tls) {
    bean.allowInsecure = outbound.tls.insecure || false;
    bean.sni = outbound.tls.server_name || '';
    bean.alpn = (outbound.tls.alpn || []).join(',');
    bean.disableSNI = outbound.tls.disable_sni || false;
    bean.caText = outbound.tls.certificate || '';
  }
  return bean;
}

/**
 * 解析 Sing-box WireGuard Outbound
 * @param {object} outbound - Outbound 对象
 * @returns {WireGuardBean} Bean 对象
 */
function parseSingboxWireguard(outbound) {
  const bean = new WireGuardBean();
  bean.name = outbound.tag;
  const peer = outbound.peers?.[0];
  bean.serverAddress = outbound.server || peer?.address || '';
  bean.serverPort = outbound.server_port || peer?.port || 51820;
  bean.privateKey = outbound.private_key || '';
  bean.peerPublicKey = outbound.peer_public_key || peer?.public_key || '';
  bean.peerPreSharedKey = outbound.pre_shared_key || peer?.pre_shared_key || '';
  bean.localAddress = (outbound.local_address || outbound.address || []).join(',');
  bean.reserved = (outbound.reserved || peer?.reserved || '').toString();
  bean.mtu = outbound.mtu || 1420;
  return bean;
}

/**
 * 解析 Sing-box SSH Outbound
 * @param {object} outbound - Outbound 对象
 * @returns {SSHBean} Bean 对象
 */
function parseSingboxSSH(outbound) {
  const bean = new SSHBean();
  bean.name = outbound.tag;
  bean.serverAddress = outbound.server;
  bean.serverPort = outbound.server_port;
  bean.username = outbound.user;
  bean.publicKey = (outbound.host_key || []).join('\n');

  if (outbound.private_key) {
    bean.authType = 'private_key';
    bean.privateKey = outbound.private_key;
    bean.privateKeyPassphrase = outbound.private_key_passphrase || '';
    bean.password = '';
  } else {
    bean.authType = 'password';
    bean.password = outbound.password;
    bean.privateKey = '';
  }
  return bean;
}

/**
 * 解析 Sing-box AnyTLS Outbound
 * @param {object} outbound - Outbound 对象
 * @returns {AnyTLSBean} Bean 对象
 */
function parseSingboxAnyTLS(outbound) {
  const bean = new AnyTLSBean();
  bean.name = outbound.tag;
  bean.serverAddress = outbound.server;
  bean.serverPort = outbound.server_port;
  bean.password = outbound.password || '';

  if (outbound.tls && outbound.tls.enabled) {
    bean.allowInsecure = outbound.tls.insecure || false;
    bean.sni = outbound.tls.server_name || '';
    bean.alpn = (outbound.tls.alpn || []).join(',');
    bean.certificates = outbound.tls.certificate || '';
    if (outbound.tls.utls && outbound.tls.utls.enabled) {
      bean.utlsFingerprint = outbound.tls.utls.fingerprint || '';
    }
    if (outbound.tls.ech && outbound.tls.ech.enabled) {
      bean.enableECH = true;
      bean.echConfig = (outbound.tls.ech.config || []).join('\n');
    }
  }

  bean.idleSessionCheckInterval = outbound.idle_session_check_interval || '';
  bean.idleSessionTimeout = outbound.idle_session_timeout || '';
  bean.minIdleSession = outbound.min_idle_session || 0;
  return bean;
}

/**
 * 解析 Sing-box Outbound
 * @param {object} outbound - Outbound 对象
 * @returns {AbstractBean} Bean 对象
 */
function parseSingboxOutbound(outbound) {
  if (!outbound || !outbound.type) {
    throw new Error("Invalid Sing-box outbound object: missing 'type' field.");
  }
  let bean;
  switch (outbound.type) {
    case 'vless':
    case 'vmess':
      bean = parseSingboxVMess(outbound);
      break;
    case 'trojan':
      bean = parseSingboxTrojan(outbound);
      break;
    case 'shadowsocks':
      bean = parseSingboxShadowsocks(outbound);
      break;
    case 'socks':
      bean = parseSingboxSocks(outbound);
      break;
    case 'http':
      bean = parseSingboxHttp(outbound);
      break;
    case 'hysteria':
    case 'hysteria2':
      bean = parseSingboxHysteria(outbound);
      break;
    case 'tuic':
      bean = parseSingboxTuic(outbound);
      break;
    case 'wireguard':
      bean = parseSingboxWireguard(outbound);
      break;
    case 'ssh':
      bean = parseSingboxSSH(outbound);
      break;
    case 'anytls':
      bean = parseSingboxAnyTLS(outbound);
      break;
    default:
      throw new Error(`Unsupported outbound type for reverse conversion: ${outbound.type}`);
  }
  bean.initializeDefaultValues();
  return bean;
}

/**
 * 将 Sing-box Outbound 对象转换为链接
 * @param {object} outbound - Outbound 对象
 * @returns {string} 链接字符串
 */
function convertOutboundToLink(outbound) {
  try {
    const bean = parseSingboxOutbound(outbound);
    if (bean) {
      return bean.toUri();
    }
    throw new Error("Failed to parse outbound into a known bean type.");
  } catch (e) {
    console.error(`[!] Failed to convert outbound to link: ${e.message}`, outbound);
    return `error://conversion-failed?message=${encodeURIComponent(e.message)}`;
  }
}

/**
 * 将 Sing-box Outbound 数组转换为链接数组
 * @param {object[]} outbounds - Outbound 对象数组
 * @returns {string[]} 链接数组
 */
function convertOutboundsToLinks(outbounds) {
  if (!Array.isArray(outbounds)) {
    throw new Error("Input must be an array of outbound objects.");
  }
  return outbounds.map(outbound => convertOutboundToLink(outbound));
}

/**
 * 解析原始内容
 * @param {string} content - 内容
 * @returns {AbstractBean[]} Bean 对象数组
 */
function parseRawContent(content) {
  const links = content.split(/[\n\s]+/).filter(Boolean);
  if (links.some(l => l.includes('://'))) {
    return links.map(parseLink).filter(Boolean);
  }
  return [];
}

// --- 工具函数 --- ]]]1

// --- 辅助函数 ---
function sbtplLog(v) {
  console.log(`[sbtpl] ${v}`)
}
function sbtplErr(v) {
  console.error(`[sbtpl.Error] ${v}`)
}
/**
 * 判断输入是否为 HTTP/HTTPS URL
 * @param {string} value - 输入字符串
 * @returns {boolean} 是否为 HTTP/HTTPS URL
 */
function isHttpSubscriptionUrl(value) {
  if (!value || typeof value !== 'string') return false;
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch (e) {
    return false;
  }
}

/**
 * 拉取订阅文本，支持 HTTP/HTTPS 与重定向
 * @param {string} urlString - 订阅地址
 * @param {number} redirectCount - 当前重定向次数
 * @returns {Promise<string>} 原始响应文本
 */
async function fetchSubscriptionText(urlString, redirectCount = 0) {
  if (redirectCount > 5) {
    throw new Error('Too many redirects while fetching subscription');
  }

  const url = new URL(urlString);
  const client = url.protocol === 'https:' ? https : http;
  sbtplLog(`fetching ${url.protocol}//${url.host}${url.pathname}${url.search}${redirectCount ? ` (redirect ${redirectCount})` : ''}`);

  return await new Promise((resolve, reject) => {
    const req = client.request(
      url,
      {
        method: 'GET',
        headers: {
          'User-Agent': 'substore-node/1.0',
          Accept: '*/*',
        },
      },
      async (res) => {
        const statusCode = res.statusCode || 0;
        sbtplLog(`response status: ${statusCode}`);

        if (statusCode >= 300 && statusCode < 400 && res.headers.location) {
          const redirectUrl = new URL(res.headers.location, url).toString();
          sbtplLog(`redirect -> ${redirectUrl}`);
          res.resume();
          try {
            resolve(await fetchSubscriptionText(redirectUrl, redirectCount + 1));
          } catch (e) {
            reject(e);
          }
          return;
        }

        if (statusCode < 200 || statusCode >= 300) {
          res.resume();
          reject(new Error(`Failed to fetch subscription: HTTP ${statusCode}`));
          return;
        }

        const chunks = [];
        res.on('data', (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          sbtplLog(`received ${text.length} chars`);
          resolve(text);
        });
      },
    );

    req.on('error', (error) => {
      sbtplErr(`request failed: ${error.message}`);
      reject(error);
    });
    req.end();
  });
}

/**
 * 归一化订阅内容，兼容 Base64/plain text
 * @param {string} rawText - 原始订阅响应
 * @returns {string} 归一化后的订阅内容
 */
function normalizeSubscriptionContent(rawText) {
  const trimmed = rawText.trim();
  if (!trimmed) return '';

  const decoded = b64Decode(trimmed).trim();
  if (decoded && (
    decoded.includes('://') ||
    decoded.includes('proxies:') ||
    decoded.includes('[Interface]') ||
    decoded.startsWith('{') ||
    decoded.startsWith('[')
  )
  ) {
    sbtplLog(`detected base64 subscription content, decoded ${decoded.length} chars`);
    return decoded;
  }
  sbtplLog('content format not recognized, using raw text');
  return trimmed;
}

/**
 * 对字符串数组去重并过滤空值
 * @param {string[]} values - 待处理字符串数组
 * @returns {string[]} 去重后的字符串数组
 */
// function uniqStrings(values) {
//   return [...new Set((values || []).filter((value) => typeof value === 'string' && value.trim()))];
// }
function getTags(proxies, regex) {
  return (regex ? proxies.filter(p => regex.test(p.tag)) : proxies).map(p => p.tag)
}
function convert2RegExp(rulePattern) {
  return new RegExp(rulePattern.replace('~', ''), rulePattern.includes('~') ? 'i' : undefined)
}
function setTemplateValue(temp, ctrlapi, mixport, logFilePath, isTunEnabled, isAndroid, isLinux, isIcmp, IsWindows, isIpv6 = false) {
  const default_mixport = 2334
  const default_ctrlapi = 9090

  const tun_tag = 'tun-in'
  const tun_inbound = {
    type: 'tun',
    tag: tun_tag,
    address: [
      '172.19.0.1/30',
      ...(isIpv6 ? ['fdfe:dcba:9876::1/126'] : []),
    ],
    mtu: 9000,
    auto_route: true,
    strict_route: true,
  }
  const route_exclude_address = [
    '10.0.0.0/8',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.0.0.0/24',
    '192.168.0.0/16',
    '255.255.255.255/32',
    'fe80::/10',
    '240e::/20'
  ]

  let config = temp;

  const finCtrlapi = ctrlapi ? parseInt(ctrlapi, 10) : (isTunEnabled ? 8790 : default_ctrlapi)
  sbtplLog(`最终 ctrlapi=${finCtrlapi}`)
  if (finCtrlapi != default_ctrlapi) {
    config.experimental.clash_api.external_controller = `[::]:${finCtrlapi}`
    sbtplLog(`📝 更新 experimental.clash_api.external_controller: ${config.experimental.clash_api.external_controller}`)
  }

  const finMixport = mixport ? parseInt(mixport, 10) : (isTunEnabled ? 2134 : default_mixport)
  sbtplLog(`最终 mixport=${finMixport}`)
  if (finMixport != default_mixport) {
    config.inbounds[0].listen_port = finMixport // WARN: HardCode! 默认第一个入站是 mix入站(如果不是需要手动调整代码)
    sbtplLog(`📝 更新 inbounds[0](即 Mix入站).listen_port: ${JSON.stringify(config.inbounds[0])}`)
  }

  if (isTunEnabled) {
    sbtplLog(`tun 入站使用`)
    if (config.route.rules[0]?.action === 'sniff') { // 默认开头一个规则是sniff的, 这里添加它的 inbound 为 tun_tag
      if (isAndroid) {
        config.inbounds.push(tun_inbound)
        sbtplLog(`使用了Android版的tun(无route_exclude_address)`)
      } else {
        tun_inbound.route_exclude_address = route_exclude_address
        sbtplLog(`📝 开启了 tun 的 route_exclude_address 功能`)
        if (isLinux) {
          const linux_tun_inbound = tun_inbound
          linux_tun_inbound.auto_redirect = true
          sbtplLog(`📝 开启了 tun 的 auto_redirect(仅Linux支持) 功能`)
          config.inbounds.push(linux_tun_inbound)
        } else if (IsWindows) {
          tun_inbound.stack = 'gvisor'
          tun_inbound.mtu = 1500
          sbtplLog(`📝 开启了 windows 的 gVisor 栈功能`)
          config.inbounds.push(tun_inbound)
        } else {
          config.inbounds.push(tun_inbound)
        }
      }
      config.route.rules[0].inbound = tun_tag
      sbtplLog(`📝 更新 route.rules[0]: ${JSON.stringify(config.route.rules[0])}`)
    }
  }

  if (isIcmp) {
    sbtplLog(`icmp 透传: (sing-box version>=1.13.0)`)
    config.route.rules.unshift({
      network: 'icmp',
      outbound: '🎯Direct',
    })
    sbtplLog(`📝 头部插入了icmp直连, 当前route.rules[0]: ${JSON.stringify(config.route.rules[0])}`)
  }

  if (isAndroid) {
    config.route.override_android_vpn = true
    sbtplLog(`📝 开启了仅android支持的 route.override_android_vpn 功能`)
  }

  if (logFilePath != undefined) {
    let trimStr = logFilePath.trim()
    if (trimStr === '') {
      delete config.log.output
      delete config.log.timestamp
      sbtplLog(`📝 删除了log.output 和 log.timestamp`)
    } else {
      config.log.output = trimStr
      config.log.timestamp = true
      sbtplLog(`📝 修改了log.output: ${config.log.output}, log.timestamp: true`)
    }
  }
  return config;
}
/**
 * 将解析出的节点注入模板配置中的 outbounds
 * @param {object} template - 模板配置
 * @param {object[]} proxies - 解析出的节点
 * @returns {object} 新的配置对象
 */
function insertProxies(template, proxies, policyFilter) {
  const config = JSON.parse(JSON.stringify(template));
  const baseOutbounds = Array.isArray(config.outbounds) ? config.outbounds : [];
  const proxyOutbounds = proxies.filter(proxy => proxy.type !== 'wireguard');
  const proxyEndpoints = proxies.filter(proxy => proxy.type === 'wireguard');

  const filterRules = policyFilter
    .split('@')
    .filter(i => i)
    .map(i => {
      let [filterPattern, tagPattern = '.*'] = i.split('-')
      const tagRegex = convert2RegExp(tagPattern)
      sbtplLog(`匹配 - ${tagRegex} 的节点将插入匹配 🌀 ${convert2RegExp(filterPattern)} 的 outbound 中`)
      return [filterPattern, tagRegex]
    })

  sbtplLog(`⓸ outbound 插入节点`)
  baseOutbounds.map(outboundItem => {
    filterRules.map(([filterPattern, tagRegex]) => {
      const outboundRegex = convert2RegExp(filterPattern)
      if (outboundRegex.test(outboundItem.tag)) {
        if (!Array.isArray(outboundItem.outbounds)) {
          outboundItem.outbounds = []
        }
        const tags = getTags(proxies, tagRegex)
        sbtplLog(`📝 ${outboundItem.tag} 匹配 ${outboundRegex}, 插入 ${tags.length} 个 - 匹配 ${tagRegex} 的节点`)
        outboundItem.outbounds.push(...tags)
      }
    })
  })

  sbtplLog(`⓹ 空 outbounds 检查`)
  baseOutbounds.map(outboundItem => {
    filterRules.map(() => {
      if (outboundItem.type.toLowerCase() !== 'direct') {
        if (!Array.isArray(outboundItem.outbounds)) {
          outboundItem.outbounds = []
        }
        if (outboundItem.outbounds.length === 0) {
          sbtplLog(`📝 ${outboundItem.tag} 的 outbounds 为空, 自动插入🌐Proxy`)
          outboundItem.outbounds.push('🌐Proxy')
        }
      }
    })
  })

  config.outbounds = [...baseOutbounds, ...proxyOutbounds];
  if (proxyEndpoints.length > 0 || Array.isArray(config.endpoints)) {
    config.endpoints = [...(config.endpoints || []), ...proxyEndpoints];
  }
  return config;
}

async function run() {
  const {
    values: {
      'subscribe-link': subLink,
      'subscription-file': subscriptionFile,
      'output-file': outputFile,
      'policy-filter': policyFilter,
      'template': templatePath,
      'tun': isTunEnabled,
      'controller-port': ctrlapi,
      'mixed-port': mixport,
      'log-file': logFilePath,
      'android': isAndroid,
      'linux': isLinux,
      'icmp': isIcmp,
      'windows': IsWindows,
      'ipv6': isIpv6,
      'version': version,
    },
  } = parseArgs({
    args: process.argv.slice(2),
    options: {
      'subscribe-link': {
        type: 'string',
        short: 's',
      },
      'subscription-file': {
        type: 'string',
        short: 'f',
      },
      'output-file': {
        type: 'string',
        short: 'o',
      },
      'policy-filter': {
        type: 'string',
        short: 'p',
      },
      'template': {
        type: 'string',
        short: 't',
      },
      'tun': {
        type: 'boolean',
        default: false,
      },
      'controller-port': {
        type: 'string',
        short: 'c',
        default: '',
      },
      'mixed-port': {
        type: 'string',
        short: 'm',
        default: '',
      },
      'log-file': {
        type: 'string',
        short: 'l',
      },
      'android': {
        type: 'boolean',
        default: false,
      },
      'linux': {
        type: 'boolean',
        default: false,
      },
      'icmp': {
        type: 'boolean',
        default: false,
      },
      'windows': {
        type: 'boolean',
        default: false,
      },
      'ipv6': {
        type: 'boolean',
        default: false,
      },
      'version': {
        type: 'boolean',
        short: 'v',
      },
    },
  })

  if (version) {
    let commit = 'unknown'
    let dirty = false
    try {
      commit = execSync('git rev-parse --short HEAD', { cwd: path.dirname(new URL(import.meta.url).pathname), encoding: 'utf8' }).trim()
      dirty = execSync('git status --porcelain', { cwd: path.dirname(new URL(import.meta.url).pathname), encoding: 'utf8' }).trim().length > 0
    } catch {}
    const suffix = dirty ? '-dirty' : ''
    console.log(`sbtpl ${pkg.version} (commit: ${commit}${suffix})`)
    process.exit(0)
  }

  if (!subLink && !subscriptionFile) {
    process.exit(1)
  }

  // handle many sub (split by '\n' or ';')
  const subLinks = (subLink || '')
    .split(/[\n;]+/)
    .map(link => link.trim())
    .filter(link => link.length > 0);

  const subscriptionFiles = (subscriptionFile || '')
    .split(/[\n;]+/)
    .map(file => file.trim())
    .filter(file => file.length > 0);

  sbtplLog(`processing ${subLinks.length} subscription link(s), ${subscriptionFiles.length} subscription file(s)`);

  // merge all sub contents
  let combinedInput = '';

  for (const subLink of subLinks) {
    sbtplLog(`input mode: ${isHttpSubscriptionUrl(subLink) ? 'url' : 'raw'} - ${subLink.substring(0, 50)}${subLink.length > 50 ? '...' : ''}`);
    const subscriptionInput = isHttpSubscriptionUrl(subLink)
      ? normalizeSubscriptionContent(await fetchSubscriptionText(subLink))
      : normalizeSubscriptionContent(subLink);
    sbtplLog(`normalized content length: ${subscriptionInput.length}`);
    combinedInput += subscriptionInput + '\n';
  }

  for (const filePath of subscriptionFiles) {
    const resolvedPath = path.resolve(filePath);
    sbtplLog(`input mode: file - ${resolvedPath}`);
    const subscriptionInput = normalizeSubscriptionContent(await fs.readFile(resolvedPath, 'utf-8'));
    sbtplLog(`normalized content length: ${subscriptionInput.length}`);
    combinedInput += subscriptionInput + '\n';
  }

  const proxies = await convertToOutbounds(combinedInput.trim());
  sbtplLog(`parsed ${proxies?.length || 0} outbounds`);

  // 加载模板（自定义或默认）
  let templateStr;
  if (templatePath) {
    const resolvedPath = path.resolve(templatePath);
    sbtplLog(`loading custom template from '${resolvedPath}'`);
    const templateRaw = await fs.readFile(resolvedPath, 'utf-8');
    templateStr = JSON.parse(templateRaw);
  } else {
    sbtplLog('using default template');
    templateStr = createTemplate('fakeip');
  }

  const confNew = setTemplateValue(templateStr, ctrlapi, mixport, logFilePath, isTunEnabled, isAndroid, isLinux, isIcmp, IsWindows, isIpv6);

  const config = insertProxies(confNew, proxies || [], policyFilter);

  const json = JSON.stringify(config, null, 2);

  if (outputFile) {
    await fs.writeFile(outputFile, json, 'utf-8');
    sbtplLog(`sing-box configuration saved to '${outputFile}'`);
  } else {
    console.log('\n');
    console.log(json);
  }
}

export {
  VMessBean, TrojanBean, ShadowsocksBean,
  buildSingboxOutbound,
  generateUUID, generateRandomBase64,
  sbtplLog, sbtplErr, safeParseInt,
}

// --- 入口 ---

import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { realpathSync } from 'node:fs'

const __filename = fileURLToPath(import.meta.url)
const isMainModule = (() => {
  try {
    return process.argv[1] && realpathSync(process.argv[1]) === __filename
  } catch {
    return false
  }
})()

if (isMainModule) {
  const subCommand = process.argv[2]
  if (subCommand === 'server') {
    const serverJs = path.join(path.dirname(__filename), 'server.js')
    try {
      execFileSync(process.execPath, [serverJs, ...process.argv.slice(3)], { stdio: 'inherit' })
    } catch (e) {
      process.exit(e.status || 1)
    }
  } else {
    run()
  }
}

// vim:fdm=marker:fmr=[[[,]]]
