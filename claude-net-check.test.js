// Run: node claude-net-check.test.js
'use strict'
const assert = require('assert')
const { verdict, SUSPECT_ISSUER } = require('./claude-net-check.js')

const R = (rows) => rows.map(([kb, ok, bad]) => ({ kb, ok, bad, why: {} }))
const cases = [
  ['clean', R([[1, 25, 0], [50, 25, 0], [300, 25, 0], [1024, 25, 0]]), 'clean'],
  ['size-dependent', R([[1, 25, 0], [50, 14, 11], [300, 10, 15], [1024, 9, 16]]), 'size'],
  ['one bad size bucket', R([[1, 25, 0], [50, 25, 0], [300, 19, 6], [1024, 25, 0]]), 'size'],
  ['a single large failure', R([[1, 25, 0], [50, 25, 0], [300, 24, 1], [1024, 25, 0]]), 'mild'],
  ['small failures only', R([[1, 20, 5], [50, 25, 0], [300, 25, 0], [1024, 25, 0]]), 'mild'],
  ['nothing gets through', R([[1, 2, 23], [50, 0, 25], [300, 0, 25], [1024, 0, 25]]), 'all'],
]
for (const [name, results, want] of cases) assert.strictEqual(verdict(results).level, want, name)

const issuers = [['AVG Web/Mail Shield Root', true], ['Avast Web/Mail Shield Root', true], ['Zscaler Inc.', true], ['Google Trust Services', false], ["Let's Encrypt", false], ['Amazon', false]]
for (const [issuer, want] of issuers) assert.strictEqual(SUSPECT_ISSUER.test(issuer), want, issuer)

console.log('all tests pass')
