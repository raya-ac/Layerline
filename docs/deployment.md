# Layerline Deployment

This runbook is for replacing a front web server on a controlled host. It assumes the binary has already passed `zig build test`, a native release build, config validation, and at least one smoke test.

## Filesystem Layout

Use predictable paths so service files, certbot, and rollback scripts agree:

```text
/usr/local/bin/layerline
/etc/layerline/server.conf
/etc/layerline/domains-enabled/*.conf
/run/layerline/admin.sock
/var/www/layerline/public
/var/lib/layerline
/var/log/layerline
```

Create a service user:

```bash
sudo useradd --system --home /var/lib/layerline --shell /usr/sbin/nologin layerline
sudo mkdir -p /etc/layerline/domains-enabled /run/layerline /var/www/layerline/public /var/lib/layerline /var/log/layerline
sudo chown -R layerline:layerline /run/layerline /var/www/layerline /var/lib/layerline /var/log/layerline
```

Install the binary and config:

```bash
zig build -Doptimize=ReleaseFast
sudo install -m 0755 zig-out/bin/layerline /usr/local/bin/layerline
sudo install -m 0644 server.conf /etc/layerline/server.conf
sudo cp -R public/. /var/www/layerline/public/
```

## Linux systemd

Install the unit:

```bash
sudo cp deploy/systemd/layerline.service /etc/systemd/system/layerline.service
sudo cp deploy/systemd/layerline.env.example /etc/layerline/layerline.env
sudo systemctl daemon-reload
sudo systemctl enable --now layerline
```

Validate and apply config edits:

```bash
sudo -u layerline /usr/local/bin/layerline --validate-config --config /etc/layerline/server.conf
sudo systemctl reload layerline
sudo journalctl -u layerline -f
```

The packaged unit validates the config file first, then asks the running process to shut down gracefully so systemd can replace it. That is the safe bridge until Layerline has in-memory config snapshot reload. The unit grants `CAP_NET_BIND_SERVICE` so Layerline can bind ports below 1024 without running as root. Keep `LimitNOFILE=1048576` unless the host has a lower global cap.

If Layerline is replacing the host's TLS edge, also install the renewal timer after `certbot certonly` has created certificates:

```bash
sudo cp deploy/systemd/layerline-cert-renew.service /etc/systemd/system/layerline-cert-renew.service
sudo cp deploy/systemd/layerline-cert-renew.timer /etc/systemd/system/layerline-cert-renew.timer
sudo systemctl daemon-reload
sudo systemctl enable --now layerline-cert-renew.timer
```

The timer runs `certbot renew` twice daily with jitter. Its deploy hook restarts Layerline only when certbot deploys a renewed certificate, which is the required bridge until live TLS material reload is implemented.

## Logs

For journald-only deployments, keep access logs on stderr:

```conf
access_log = stderr
```

For file-based collection, write JSON lines to `/var/log/layerline/access.log` and keep `/var/log/layerline` owned by the `layerline` user:

```conf
access_log = /var/log/layerline/access.log
```

Use `journalctl -u layerline` for startup, parse, and renewal errors. Use the access log for request-level fields such as method, path, protocol, status, bytes, latency, handler, and upstream target.

## Kernel and Limits

For busy hosts, put the local equivalent of this in `/etc/sysctl.d/90-layerline.conf`:

```text
fs.file-max = 2097152
net.core.somaxconn = 65535
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_tw_reuse = 1
```

Apply with:

```bash
sudo sysctl --system
```

Keep the systemd `LimitNOFILE` and the shell `ulimit -n` aligned with expected connection counts. Compression-enabled deployments raise Layerline worker stack size to at least 512 KiB, so test memory pressure before enabling huge connection fan-in and dynamic gzip together.

## macOS launchd

Install paths match the plist:

```bash
sudo mkdir -p /etc/layerline /var/log/layerline
sudo install -m 0755 zig-out/bin/layerline /usr/local/bin/layerline
sudo install -m 0644 server.conf /etc/layerline/server.conf
sudo cp deploy/launchd/dev.layerline.layerline.plist /Library/LaunchDaemons/dev.layerline.layerline.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/dev.layerline.layerline.plist
sudo launchctl enable system/dev.layerline.layerline
```

Restart:

```bash
sudo launchctl kickstart -k system/dev.layerline.layerline
```

## TLS and ACME

Layerline can serve ACME HTTP-01 challenge files from `letsencrypt_webroot`. Use certbot webroot semantics: point the config at the public root, and Layerline serves `<webroot>/.well-known/acme-challenge/<token>`. Older configs that point directly at the challenge directory are still accepted.

```bash
sudo certbot certonly --webroot -w /var/www/layerline/public -d example.com -d www.example.com
```

When replacing an existing reverse proxy, you can usually issue the first cert while the proxy still owns ports 80/443 as long as it forwards `/.well-known/acme-challenge/` to Layerline and `letsencrypt_webroot` points at the same webroot used by certbot. Do not stop the old edge until the new cert files exist and `layerline --validate-config` can load them.

Once Layerline owns the edge, enable the plaintext redirect listener. It binds `http_redirect_port`, serves ACME HTTP-01 challenges from `letsencrypt_webroot`, and redirects every other request to HTTPS while preserving host, path, and query.

```conf
letsencrypt_webroot = /var/www/layerline/public
letsencrypt_renew = true
letsencrypt_renew_interval_ms = 43200000
tls = true
tls_cert = /etc/letsencrypt/live/example.com/fullchain.pem
tls_key = /etc/letsencrypt/live/example.com/privkey.pem
http_redirect = true
http_redirect_port = 80
http_redirect_https_port = 443
http_redirect_status = 308
```

With `letsencrypt_renew = true`, Layerline starts a background `certbot renew --webroot` loop. For production, prefer the systemd `layerline-cert-renew.timer` because its certbot deploy hook restarts Layerline only after a renewed certificate is deployed. Renewal updates the certificate files on disk; until in-memory hot reload lands, the running process must restart to pick up new TLS material.

## Smoke Checks

Run these before moving traffic:

```bash
/usr/local/bin/layerline --validate-config --config /etc/layerline/server.conf
curl -fsS http://127.0.0.1:8080/health
curl -fsSI -H 'Accept-Encoding: gzip' http://127.0.0.1:8080/ | grep -i '^Content-Encoding: gzip'
printf 'status\n' | nc -U /run/layerline/admin.sock
printf 'validate\n' | nc -U /run/layerline/admin.sock
printf 'certs\n' | nc -U /run/layerline/admin.sock
./scripts/benchmark-layerline.sh --verify-only --no-h3
```

For a local release candidate before copying files onto the host, run the self-starting verifier:

```bash
./scripts/verify-layerline.sh
```

If HTTP/2 is enabled through native TLS or h2c testing, add:

```bash
curl --http2-prior-knowledge -fsSI http://127.0.0.1:8080/
```

## Rollback

Keep release directories and switch a symlink:

```text
/opt/layerline/releases/<git-sha>/layerline
/opt/layerline/current -> /opt/layerline/releases/<git-sha>
```

Point `ExecStart` at `/opt/layerline/current/layerline`. Roll back by moving the symlink, validating the old config, and restarting:

```bash
sudo ln -sfn /opt/layerline/releases/<previous-sha> /opt/layerline/current
sudo /opt/layerline/current/layerline --validate-config --config /etc/layerline/server.conf
sudo systemctl restart layerline
```
