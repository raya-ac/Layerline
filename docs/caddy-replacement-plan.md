# replacing caddy on a host

i already run Layerline in front of sites. that tells me it can handle that
setup. it doesn't tell me it can replace every Caddyfile or nginx config.

## before switching

- [ ] List the hostnames and what each one needs: redirects, certificates,
  static paths, PHP, upstreams, uploads and WebSockets. Include anything that
  only works because of a setting in the old proxy.
- [ ] Keep an exact copy of the current binary, configs and service settings.
  Record what is actually running. Check that the old release can still start.
- [ ] Use a candidate built from the exact commit under test. Keep the tool
  versions, build flags, source and binary hashes, and raw check results.
  A passing GitHub job isn't permission to restart the live service.
- [ ] Run the candidate on separate listeners. Validate every config and test
  the URLs with the right Host, SNI, protocol and origin trust.
  Compare status, redirects and important response bytes with the live server.
- [ ] Exercise reload, shutdown, descriptor and memory pressure under the real
  service manager. Rehearse old to new and back before moving traffic.
- [ ] After switching, check the running binary hash, readiness and logs.
  Recheck the public sites, app routes and webmail. Roll back on a regression.

## where i'd still keep caddy

if the site needs something Layerline can't do yet, don't replace its proxy.
in particular, first-boot HTTP-01 isn't self-contained, the TCP listener has a
narrower TLS profile than a general-purpose server, and HTTP/3 is experimental.
a good curl result against `/health` says nothing about a long upload or a busy
upstream.

leave browser admin and `/test.php` off unless there's a reason to enable them.
for config, service and rollback commands, see [deployment](deployment.md).
for the protocol and resource gaps, see [the roadmap](roadmap.md) and
[security notes](security.md).
