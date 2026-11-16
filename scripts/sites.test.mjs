import assert from 'node:assert/strict'
import test from 'node:test'
import { QUICK_SITES, chipSelected, quickHost } from '../src/sites.ts'

test('quick sites only fill the existing hostname field', () => {
  assert.deepEqual(
    QUICK_SITES.map((site) => site.label),
    ['百度', '淘宝', '腾讯'],
  )
  assert.deepEqual(
    QUICK_SITES.map((site) => quickHost(site.host)),
    ['www.baidu.com', 'www.taobao.com', 'www.qq.com'],
  )
  assert.equal(quickHost('www.google.com'), null)
  assert.equal(quickHost('https://www.baidu.com'), null)
  assert.ok(!QUICK_SITES.some((site) => site.host.includes('google')))
})

test('an empty field still selects the default baidu chip', () => {
  assert.equal(chipSelected('', 'www.baidu.com'), true)
  assert.equal(chipSelected('  ', 'www.baidu.com'), true)
  assert.equal(chipSelected('www.taobao.com', 'www.taobao.com'), true)
  assert.equal(chipSelected('www.taobao.com', 'www.baidu.com'), false)
  assert.equal(chipSelected('WWW.QQ.COM', 'www.qq.com'), true)
})
