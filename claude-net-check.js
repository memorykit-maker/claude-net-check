#!/usr/bin/env node
// claude-net-check: is something on your network path breaking big HTTPS uploads to the Claude API?
// POSTs filler bytes of growing size to the API host with NO API key and NO real content; the server
// just answers 4xx. What is measured is whether the TLS connection survives the upload.
// Usage: node claude-net-check.js [--runs 25] [--host api.anthropic.com] [--timeout 15000]
'use strict'
const https = require('https')
const tls = require('tls')

const SIZES_KB = [1, 50, 300, 1024]
const SUSPECT_ISSUER = /avg|avast|kaspersky|bitdefender|eset|norton|mcafee|sophos|zscaler|fortinet|fortigate|palo alto|netskope|blue coat|symantec|web shield|mail shield|inspection|proxy|firewall/i

const arg = (name, fallback) => {
  const i = process.argv.indexOf('--' + name)
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback
}
const RUNS = Math.max(1, parseInt(arg('runs', '25'), 10) || 25)
const HOST = arg('host', 'api.anthropic.com')
const TIMEOUT_MS = parseInt(arg('timeout', '15000'), 10) || 15000

const issuerOf = (host) =>
  new Promise((resolve) => {
    const s = tls.connect({ host, port: 443, servername: host }, () => {
      const c = s.getPeerCertificate()
      s.end()
      resolve(c && c.issuer ? c.issuer.O || c.issuer.CN || '(unknown)' : '(unknown)')
    })
    s.setTimeout(10000, () => { s.destroy(); resolve(undefined) })
    s.on('error', () => resolve(undefined))
  })

const upload = (agent, sizeKb) =>
  new Promise((resolve) => {
    const size = sizeKb * 1024
    const req = https.request(
      { host: HOST, path: '/v1/messages', method: 'POST', agent, headers: { 'content-type': 'application/json', 'content-length': size } },
      (res) => { res.resume(); res.on('end', () => resolve({ ok: true })) },
    )
    req.on('error', (e) => resolve({ ok: false, err: e.code || e.message }))
    req.setTimeout(TIMEOUT_MS, () => req.destroy(new Error('timeout')))
    req.end(Buffer.alloc(size, 97))
  })

// results: [{ kb, ok, bad, why }]; returns { level: 'clean' | 'size' | 'all' | 'mild', text }
const verdict = (results) => {
  const rate = (r) => r.bad / (r.ok + r.bad)
  const small = results[0]
  const big = results.filter((r) => r.kb >= 50)
  const worstBig = Math.max(...big.map(rate))
  if (rate(small) >= 0.5 && worstBig >= 0.5) {
    return { level: 'all', text: 'Almost nothing gets through, even small requests. That is a blocked or broken connection (firewall, proxy, VPN, DNS), not the size-dependent fault this tool looks for.' }
  }
  if (rate(small) < 0.1 && worstBig >= 0.2) {
    return { level: 'size', text: 'Small requests are fine but larger uploads fail in bursts. Something between you and the API is damaging or resetting long TLS transfers. Suspects, most likely first: antivirus or firewall "HTTPS scanning" (even with the shield off, its network drivers stay loaded), a VPN or corporate proxy, then the router or ISP. A/B it: run this again over a phone hotspot and over a different NIC (Wi-Fi vs Ethernet). If a hotspot is clean, it is your network; if it fails everywhere, it is this PC.' }
  }
  if (results.some((r) => r.bad > 0)) {
    return { level: 'mild', text: 'A few uploads failed. Rerun to see whether it repeats; one-off failures can be ordinary internet noise.' }
  }
  return { level: 'clean', text: 'All uploads completed. Your network path handles large TLS uploads fine, so look elsewhere for your Claude Code errors.' }
}

const main = async () => {
  console.log('Checking ' + HOST + ' (' + RUNS + ' uploads per size; sends filler bytes only, no key, no real data)')
  const issuer = await issuerOf(HOST)
  if (issuer === undefined) console.log('Certificate issuer: could not read it')
  else {
    console.log('Certificate issuer: ' + issuer)
    if (SUSPECT_ISSUER.test(issuer)) {
      console.log('  WARNING: that looks like a security product or proxy re-signing HTTPS traffic (TLS interception). That alone can cause errors like EPROTO.')
    }
  }
  const agent = new https.Agent({ keepAlive: true, maxSockets: 1 })
  const results = []
  for (const kb of SIZES_KB) {
    let ok = 0
    let bad = 0
    const why = {}
    for (let i = 0; i < RUNS; i++) {
      const r = await upload(agent, kb)
      if (r.ok) ok++
      else { bad++; why[r.err] = (why[r.err] || 0) + 1 }
    }
    results.push({ kb, ok, bad, why })
    console.log(String(kb).padStart(5) + ' KB: ok ' + ok + '/' + RUNS + '  failed ' + bad + (bad ? '  ' + JSON.stringify(why) : ''))
  }
  agent.destroy()
  const v = verdict(results)
  console.log('\n' + v.text)
  process.exitCode = v.level === 'clean' ? 0 : 1
}

if (require.main === module) main()
module.exports = { verdict, SUSPECT_ISSUER }
