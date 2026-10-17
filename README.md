# claude-net-check

Is something on your network breaking big HTTPS uploads to the Claude API?

If Claude Code keeps dying with `API Error: Unable to connect to API (EPROTO)`, `ECONNRESET`, or `bad record mac` / `TLSV1_ALERT_DECODE_ERROR`, but your internet otherwise works, this one-file script tells you whether the fault is on your network path and not in Claude Code.

```
node claude-net-check.js
```

Needs Node.js (tested on v24; it uses only Node's standard library, so older versions should work but haven't been tried). No dependencies, nothing to install.

## What it does

It sends filler bytes (the letter "a") to `api.anthropic.com` in growing sizes, 1 KB, 50 KB, 300 KB and 1 MB, 25 times each, and counts how many complete. It sends **no API key and no real content**; the server just answers with an error status. What is being tested is whether the TLS connection survives the upload. It also prints the certificate issuer, so you can see if a security product is re-signing your HTTPS traffic.

Example from a machine with the fault:

```
Certificate issuer: Google Trust Services
    1 KB: ok 25/25  failed 0
   50 KB: ok 15/25  failed 10  {"ERR_SSL_SSL/TLS_ALERT_BAD_RECORD_MAC":7,"EPROTO":3}
  300 KB: ok 10/25  failed 15  {"ERR_SSL_SSL/TLS_ALERT_BAD_RECORD_MAC":14,"EPROTO":1}
 1024 KB: ok 13/25  failed 12  {"ERR_SSL_SSL/TLS_ALERT_BAD_RECORD_MAC":11,"ECONNRESET":1}
```

The signature is: **small requests always pass, big ones fail in bursts.** That is not a Claude Code bug. It points at something between you and the API that damages long TLS transfers.

## Reading the result

| Verdict | Meaning |
|---|---|
| All uploads completed | Your network path is fine. Look elsewhere. |
| Small fine, large fail | The fault this tool is for. Suspects below. |
| A few failed | Rerun. One-offs can be ordinary internet noise. |
| Almost everything fails | Blocked or broken connection (firewall, proxy, VPN, DNS), not this fault. |

Exit code is 0 when clean and 1 otherwise.

## If it flags a size-dependent fault

Work out which layer it is with A/B tests, one change at a time, rerunning the script each time:

1. **Different network:** turn on your phone's hotspot, join it, rerun. Clean means your router or ISP; still failing means it's this PC.
2. **Different adapter:** switch between Wi-Fi and Ethernet. Same result on both rules out the network card and its driver.
3. **Security software:** antivirus and firewall "HTTPS scanning" or "Web Shield" features can break TLS even when switched off, because their network drivers stay loaded. Check whether the script warns about the certificate issuer, then try disabling or uninstalling the product.
4. **VPN or corporate proxy:** disconnect and rerun.

## Options

```
node claude-net-check.js --runs 10               # fewer uploads per size (about 14 MB total at 10)
node claude-net-check.js --host api.anthropic.com
node claude-net-check.js --timeout 15000         # ms per upload
```

Default is about 34 MB of upload in total.

## Status, honestly

- The verdict logic and the interception check have unit tests (`node claude-net-check.test.js`, all pass).
- Run for real on one Windows 11 machine, where it reproduced a real fault (large uploads failing with `BAD_RECORD_MAC`, `EPROTO` and `ECONNRESET`). Not run on macOS or Linux, though it uses only Node's standard library.
- The tool says where the problem *isn't*. It can point at a layer; it can't prove which product is guilty. The suspect list is a starting order, not a diagnosis.
- Read-only: it changes nothing on your machine.

MIT licensed.
