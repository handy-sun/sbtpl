# Server Config Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a safe `sbtpl server -i/--import <path>` workflow that converts supported sing-box server inbounds into sbtpl metadata while preserving the configured server IP.

**Architecture:** Keep sing-box-to-meta conversion in a pure exported function so protocol mapping and validation can be tested without process exits or filesystem setup. Add a small filesystem orchestration function that reads the import file, loads current metadata, validates the complete replacement, and saves only after success; wire it into the existing `serverDispatch` option parser.

**Tech Stack:** Node.js 18+ ESM, `node:util.parseArgs`, `fs/promises`, built-in `node:test`, and `assert/strict`.

---

### Task 1: Pure configuration conversion

**Files:**
- Modify: `test/server.test.js`
- Modify: `node/server.js`

- [ ] **Step 1: Write failing mapping tests**

Import a new `importServerConfig` export and test a configuration containing VMess, Trojan certificate TLS, Shadowsocks, and an unsupported inbound. Assert that it returns replacement protocols, preserves the supplied current IP and unrelated metadata, maps log level/timestamp/output, retains Trojan certificate paths, and returns one skip warning.

```js
const result = importServerConfig(config, {
  ip: '203.0.113.10',
  protocols: [{ type: 'vmess', port: 1, uuid: 'old' }],
  settings: { futureSetting: 'kept' },
  extra: 'kept',
})

assert.equal(result.meta.ip, '203.0.113.10')
assert.equal(result.meta.extra, 'kept')
assert.equal(result.meta.settings.futureSetting, 'kept')
assert.deepEqual(result.meta.protocols[1], {
  type: 'trojan',
  port: 443,
  password: 'trojan-secret',
  tlsMode: 'self-signed',
  domain: 'example.com',
  certificatePath: '/srv/tls/server.crt',
  keyPath: '/srv/tls/server.key',
})
assert.equal(result.warnings.length, 1)
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run: `node --test test/server.test.js`

Expected: FAIL because `importServerConfig` is not exported.

- [ ] **Step 3: Implement minimal validation and mapping**

Add boundary helpers for object checks, non-empty strings, valid ports, and exactly-one-user credentials. Implement `importServerConfig(config, currentMeta)` to:

```js
return {
  meta: normalizeMeta({
    ...currentMeta,
    protocols,
    settings: {
      ...(currentMeta.settings || {}),
      serverLogLevel: importedLog.level,
      serverLogTimestamp: importedLog.timestamp,
      serverLogFile: importedLog.output,
    },
  }),
  warnings,
}
```

Throw `Error` before returning when any supported inbound is malformed, a supported type is duplicated, or no supported inbound exists. Warning strings must identify skipped inbound indices and types without including credentials.

- [ ] **Step 4: Run the focused tests and confirm GREEN**

Run: `node --test test/server.test.js`

Expected: all tests pass.

- [ ] **Step 5: Commit the pure conversion slice**

Run: `git add node/server.js test/server.test.js && git commit -m "feat(server): parse imported sing-box configs"`

### Task 2: Preserve generated log and TLS details

**Files:**
- Modify: `test/server.test.js`
- Modify: `node/server.js`

- [ ] **Step 1: Write failing round-trip tests**

Extend `buildServerLog` coverage to expect an imported `serverLogLevel`, and extend Trojan inbound coverage to expect custom `certificatePath` and `keyPath` values:

```js
assert.deepEqual(buildServerLog({
  serverLogLevel: 'warn',
  serverLogTimestamp: true,
  serverLogFile: '/var/log/sing-box.log',
}), {
  level: 'warn',
  timestamp: true,
  output: '/var/log/sing-box.log',
})
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run: `node --test test/server.test.js`

Expected: FAIL because log level is hardcoded and Trojan certificate paths are hardcoded.

- [ ] **Step 3: Implement minimal round-trip support**

Add `serverLogLevel: 'info'` to defaults, normalize it as a non-empty string, use it in `buildServerLog`, and use `entry.certificatePath`/`entry.keyPath` with existing paths as fallbacks in `PROTOCOL_REGISTRY.trojan.buildServerInbound`.

- [ ] **Step 4: Run the focused tests and confirm GREEN**

Run: `node --test test/server.test.js`

Expected: all tests pass.

- [ ] **Step 5: Commit the round-trip slice**

Run: `git add node/server.js test/server.test.js && git commit -m "feat(server): preserve imported server settings"`

### Task 3: Filesystem import and CLI wiring

**Files:**
- Modify: `test/server.test.js`
- Modify: `node/server.js`

- [ ] **Step 1: Write failing filesystem and CLI tests**

Use `mkdtemp`, a custom meta path, and `spawnSync` to verify:

```js
const result = spawnSync(process.execPath, [serverScript, '-i', importPath, '--meta', metaPath], {
  encoding: 'utf8',
})
assert.equal(result.status, 0)
assert.match(result.stdout, /imported 1 supported inbound/)
```

Add a second invocation with malformed input and assert a non-zero exit plus byte-for-byte unchanged metadata.

- [ ] **Step 2: Run the focused tests and confirm RED**

Run: `node --test test/server.test.js`

Expected: FAIL because `-i/--import` is not parsed or dispatched.

- [ ] **Step 3: Implement filesystem orchestration and dispatch**

Add the parseArgs option:

```js
'import': { type: 'string', short: 'i' },
```

Add `serverImport(importPath, metaPath)` to read UTF-8 JSON, report readable path/JSON/validation errors without credential values, call the pure converter, and save only the validated result. In `serverDispatch`, reject combining `--import` with a subcommand; otherwise import and return before the switch.

- [ ] **Step 4: Run the focused tests and confirm GREEN**

Run: `node --test test/server.test.js`

Expected: all tests pass, including unchanged metadata after a failed import.

- [ ] **Step 5: Commit the CLI slice**

Run: `git add node/server.js test/server.test.js && git commit -m "feat(server): add config import flag"`

### Task 4: User documentation and final verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document the public CLI contract**

Add examples for both flag forms and a table row describing replacement semantics, preserved IP, supported inbound types, and warnings for unsupported inbounds.

- [ ] **Step 2: Run documentation and placeholder checks**

Run: `rg -n "server (--import|-i)|导入" README.md docs/superpowers/specs/2026-07-23-server-config-import-design.md`

Expected: the README and design both describe the import feature; no incomplete placeholders appear.

- [ ] **Step 3: Run full verification**

Run: `npm test`

Expected: zero failing tests.

Run: `node node/server.js --import /path/that/does/not/exist --meta /tmp/sbtpl-import-check/meta.json`

Expected: non-zero exit with a concise read error and no metadata file created.

Run: `npm audit --omit=dev`

Expected: no critical or high vulnerabilities.

- [ ] **Step 4: Review and commit documentation**

Inspect `git diff`, scan added lines for secrets and dangerous execution, then run:

`git add README.md && git commit -m "docs(server): document config import"`
