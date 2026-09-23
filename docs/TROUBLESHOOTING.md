# Troubleshooting

Issues the ShellCrash/mihomo community hits most often, and how they apply
to RustCrash.

## Gateway/旁路由: devices point gateway+DNS at the box, still no proxy

The most common community report. Checklist:

1. **Client IPv6 DNS bypasses the box** (top cause): if LAN devices have
   IPv6 DNS (common on iOS/macOS), their DNS goes straight to the ISP —
   the hijack on the box never sees it. Fix: enable `ipv6_enabled` so the
   ip6 DNS hijack applies, or disable IPv6 RA/DNS on the client side.
2. **Browser "secure DNS"** (DoH in the browser) bypasses the hijack
   entirely — disable it in the browser, or the box cannot intercept it.
3. **Only proxy works (7890), transparent doesn't**: the generated kernel
   config carries the listeners (`mixed/redir/tproxy-port` = proxy_port);
   if you bring your own config, make sure it listens on the same port
   the firewall redirects to.
4. **Nodes work but websites fail with cert errors**: DNS pollution in
   redir-host mode — switch `dns_mode` to `fake-ip`, or use encrypted
   upstream DNS in the generated dns section.
5. **Encrypted DNS (DoH/DoT) unreachable**: some regions block foreign
   encrypted DNS; the generated config defaults to CN-friendly DoH
   (223.5.5.5 / doh.pub) — replace `nameserver` in the general section if
   you need others.

## Boot autostart fails intermittently

The generated systemd/OpenRC/init.d/rc.local entries wait (bounded 30 s)
for a default route before starting the supervisor — the network-not-ready
race is the #1 community autostart cause. If your firmware resets firewall
rules at boot (some vendor firmwares do), re-apply: `crash firewall apply`.

## Chinese sites break in bypass/旁路由 mode with CN-IP bypass

Community issue #1124: CN-IP bypass requires IP forwarding enabled on the
box (`net.ipv4.ip_forward=1`), or LAN clients' packets die at the box.

## coexistence with ad-blockers / SmartDNS / other hijackers

Transparent proxying hijacks LAN traffic and DNS; two hijackers fight.
Use `ip_filter` (source exclusions) or the per-device MAC filter to split
which devices go through the proxy.

## Ping doesn't work through the proxy

ICMP is not proxied by mihomo/sing-box — use curl or a browser to test
(a very common community misconception).

## Open proxy warning

Prerouting hijack is scoped to `hijack_subnets` (default: RFC1918) so WAN
traffic is never redirected into the proxy. Keep it that way unless you
fully control the inbound firewall.
