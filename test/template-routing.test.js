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

  test(`${templatePath} downloads rule-sets with sing-box 1.12 fields`, async () => {
    const config = JSON.parse(await readFile(templatePath, 'utf8'))

    assert.equal(Object.hasOwn(config, 'http_clients'), false)
    assert.equal(Object.hasOwn(config.route, 'default_http_client'), false)
    assert.equal(config.dns.independent_cache, true)

    for (const ruleSet of config.route.rule_set) {
      assert.equal(ruleSet.download_detour, '🎯Direct')
    }
  })
}
