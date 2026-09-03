import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createTemplate } from '../substore/template.js'

const templateModes = [
  ['substore/template.json', 'fakeip'],
  ['substore/real-dns.json', 'real-dns'],
  ['substore/real-dns-nosniff.json', 'real-dns-nosniff'],
]

for (const [templatePath, mode] of templateModes) {
  test(`${templatePath} is generated from the shared template`, async () => {
    const config = JSON.parse(await readFile(templatePath, 'utf8'))
    assert.deepEqual(config, createTemplate(mode))
  })

  test(`${templatePath} keeps Steam services proxied and game downloads direct`, async () => {
    const config = JSON.parse(await readFile(templatePath, 'utf8'))
    const steamSelector = config.outbounds.find(outbound => outbound.tag === '🎮Steam')

    assert.deepEqual(steamSelector, {
      tag: '🎮Steam',
      type: 'selector',
      outbounds: ['⚡UrlTest', '🎯Direct'],
      interrupt_exist_connections: true,
    })

    const steamRuleSets = new Set([
      'game-download',
      'geosite-steam',
      'geosite-category-games',
      'geosite-dmm',
    ])
    const steamRules = config.route.rules.filter(rule => {
      const ruleSets = Array.isArray(rule.rule_set) ? rule.rule_set : [rule.rule_set]
      return ruleSets.some(ruleSet => steamRuleSets.has(ruleSet))
    })

    assert.deepEqual(steamRules, [
      { rule_set: 'game-download', outbound: '🎯Direct' },
      { rule_set: 'geosite-steam', outbound: '🎮Steam' },
      { rule_set: ['geosite-category-games', 'geosite-dmm'], outbound: '🎯Direct' },
    ])
  })

  test(`${templatePath} uses the sing-box 1.14 HTTP client migration`, async () => {
    const config = JSON.parse(await readFile(templatePath, 'utf8'))

    assert.deepEqual(config.http_clients, [
      { tag: 'direct-http', domain_resolver: 'dns_direct' },
    ])
    assert.equal(config.route.default_http_client, 'direct-http')
    assert.equal(Object.hasOwn(config.dns, 'independent_cache'), false)

    for (const ruleSet of config.route.rule_set) {
      assert.equal(Object.hasOwn(ruleSet, 'download_detour'), false)
    }
  })
}
