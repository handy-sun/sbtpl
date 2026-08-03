import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

const templatePaths = [
  'substore/template.json',
  'substore/real-dns.json',
]

for (const templatePath of templatePaths) {
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
}
