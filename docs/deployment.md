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

The packaged unit validates the config file first, then sends `SIGHUP` so Layerline can load a compatible config snapshot without dropping existing connections. Listener-bound edits still need `sudo systemctl restart layerline`. The unit grants `CAP_NET_BIND_SERVICE` so Layerline can bind ports below 1024 without running as root. Its file-descriptor ceiling is `LimitNOFILE=65536`; adjust it for the intended connection count and upstream pools without exceeding the host's global limits.

The unit uses `Type=notify` and `NotifyAccess=main`. Layerline sends native
`READY=1` only after certificate setup, all configured listener binds and
background-worker creation succeed. `systemctl start` waits for that signal;
a failed listener or an unavailable/full notification socket fails startup.
The default start timeout is 120 seconds. Increase `TimeoutStartSec` if your
certificate setup legitimately needs longer. Standalone operation without
`NOTIFY_SOCKET` does not need systemd or libsystemd.

`systemctl show layerline -p StatusText -p MainPID` exposes startup, reload and
drain status. Reloads are serialized. A rejected reload returns to ready with
`Reload rejected; previous configuration remains active`; the old snapshot
continues serving. `systemctl reload` validates before sending the signal but
does not wait for the asynchronous in-process reload. Check the status and
journal for its result. Shutdown is terminal: a finishing reload cannot send
ready after the stopping notification. Validation and admin CLI invocations
send no lifecycle messages, and child commands receive none of the inherited
notify/watchdog environment variables.
Runtime send failures increment `layerline_supervisor_notification_failures_total`
instead of logging while the lifecycle lock is held. A missing or backed-up
manager must not make a reload or the shutdown guard wait on stderr.

Readiness means the configured server endpoints are prepared, not that every
upstream is healthy. Watchdog heartbeats and socket activation are not implemented;
do not enable `WatchdogSec` or assume inherited listener descriptors are used.
The native implementation follows the [systemd notification protocol](https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html)
for filesystem and Linux abstract Unix datagram sockets. Other notification
transports are unsupported. When rolling back to an older binary without notify
support, restore its matching service unit before restarting it.

The runtime verifier includes Linux datagram tests. On an isolated Linux host,
`sudo python3 scripts/verify-systemd-notify.py /absolute/path/to/layerline --systemd`
also tests real manager activation, delayed certificate setup, reload outcomes,
listener failure and shutdown using disposable transient services.

If Layerline is replacing the host's TLS edge, also install the renewal timer after `certbot certonly` has created certificates:

```bash
sudo cp deploy/systemd/layerline-cert-renew.service /etc/systemd/system/layerline-cert-renew.service
sudo cp deploy/systemd/layerline-cert-renew.timer /etc/systemd/system/layerline-cert-renew.timer
sudo systemctl daemon-reload
sudo systemctl enable --now layerline-cert-renew.timer
```

The timer runs `certbot renew` twice daily with jitter. Its deploy hook asks systemd to reload or restart Layerline only when certbot deploys a renewed certificate; with the packaged unit, compatible certificate material updates use the same `SIGHUP` reload path.

## Logs

For journald-only deployments, keep access logs on stderr:

```conf
access_log = stderr
```

For file-based collection, write JSON lines to `/var/log/layerline/access.log` and keep `/var/log/layerline` owned by the `layerline` user:

```conf
access_log = /var/log/layerline/access.log
```

Use `journalctl -u layerline` for startup, parse, and renewal errors. Use the access log for request-level fields such as request ID, method, path, protocol, status, bytes, latency, handler, and upstream target.

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

The packaged service adds a Linux cgroup boundary: `MemoryHigh=1G`,
`MemoryMax=1536M`, `MemorySwapMax=0` and `TasksMax=2048`. These include Layerline's child processes and
threads, unlike the application allocator budget. `MemoryHigh` causes reclamation
and throttling; the hard maximum can trigger an OOM kill and a service restart.
`OOMPolicy=stop` makes a child OOM stop the unit rather than leaving a partly
failed service running; `Restart=always` then restarts it.
Swap is disabled for the unit so oversized child allocations cannot consume
host swap as an alternative to the resident-memory limit.
These are last-resort host protection, not graceful overload handling. Review
them alongside connection counts, stack settings and external commands. Raise
them in a service drop-in when deliberately sizing a larger deployment. See the
[systemd resource-control reference](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html).

Layerline owns its Zig I/O runtime rather than using the default unbounded
concurrent pool. `io_thread_limit` defaults to 128 (range 8 to 4096), and
`io_stack_size` defaults to 1048576 bytes (range 1 MiB to 64 MiB). Both are
restart-only settings, also available as `--io-thread-limit` and `--io-stack-size`.
I/O task allocations and bootstrap storage share the application heap cap; the
`io` allocator tier additionally caps retained task metadata at 16 MiB. Pool
admission does not run rejected DNS/dial work inline. Exhaustion can reject a
backend attempt or stream; it must not silently create more workers. Metrics
report retained and busy I/O threads, configured limits, stacks and allocator use.
Idle pool threads can remain allocated for reuse up to the configured ceiling.

`descriptor_limit` defaults to 4096 managed reservations (range 32 to 1048576),
also available as `--descriptor-limit`, and requires a restart. Linux/macOS clamp
it to startup soft nofile minus inherited handles and 32 handles of headroom;
insufficient room for the minimum fails startup. The control partition is one
quarter of that effective limit capped at 32, plus two separate rejection slots.
The remainder covers ordinary listeners, clients, upstreams, files, pipes and
pending operations. H2 connections also retain interrupt pipes. Size this budget
alongside connection counts, not as their synonym. Descriptor metrics report
requested/effective/kernel/inherited values and per-pool ownership, reservations,
peaks and rejections. Private resolver/filesystem allowances are charged without
claiming to count every underlying OS handle. Runtime changes to the OS limit
do not refresh the startup snapshot. Other platforms lack this adapter.

`python3 scripts/verify-descriptor-budgets.py /absolute/path/to/layerline` runs
isolated low-RLIMIT children, fills ordinary capacity, verifies protected Unix
control and reload, then checks overload framing, partial CGI rollback and
recovery on plaintext/TLS H1/H2. It does not pressure the production process.

The heap cap is still not RSS or virtual-address-space accounting. Stack guards,
TLS/runtime overhead, kernel buffers and child memory need the OS boundary above.
Standalone/non-systemd deployments must provide equivalent OS limits themselves.
macOS hostname dialing now resolves through an owned mode of the same executable
so backend deadlines, canceled HTTP/2 work and shutdown can kill/reap a stalled
libc lookup. Keep that executable available at its absolute, trusted path during
operation (prefer immutable release paths). Helpers receive no inherited
environment and never load server configuration. They share command admission
and descriptor limits. The system resolver policy is retained, with an explicit
128-address reply cap and no DNS cache added. Linux keeps its existing in-process
cancellable resolver; no additional executable or resolver dependency is needed.
Blocking kernel/filesystem/spawn operations remain outside a hard time guarantee.

CGI and helper execs now inherit only their owned standard I/O pipes. Linux 5.9+
uses `close_range`; older kernels or restricted syscall policies need a trusted,
accessible `/proc/self/fd` for the raw-syscall fallback. If both mechanisms fail,
the command is not executed. macOS uses the native spawn descriptor allowlist.
High inherited handles are removed from the child even above a lowered soft
nofile limit; the parent's handles remain untouched. This does not restrict a
command's filesystem/network access, environment or credentials. Native spawn
and other blocking kernel operations are not a hard realtime deadline guarantee.
`python3 scripts/verify-child-descriptors.py /absolute/path/to/layerline` exercises
isolated inheritable handles, CGI/helper launches and concurrent HTTP/2 churn;
the test launcher needs a hard nofile limit of at least 4097 to create its high
handle before lowering its own soft limit to 128.

`sudo python3 scripts/verify-runtime-budgets.py /absolute/path/to/layerline --systemd`
checks the packaged limits against real cgroup/process files, then deliberately
exhausts a separate 64 MiB transient unit with a certificate helper. Run it on an
isolated acceptance host; it does not change or pressure the production service.

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

With `letsencrypt_renew = true`, Layerline starts a background `certbot renew --webroot` loop. For production, prefer the systemd `layerline-cert-renew.timer` because its certbot deploy hook reloads Layerline only after a renewed certificate is deployed. Renewal updates the certificate files on disk, and `SIGHUP` reload picks up compatible TLS material without a full process restart. Operators can also run `cert-renew` through the local admin socket to perform the configured renewal and then reload TLS material for new connections.

## Smoke Checks

Run these before moving traffic:

```bash
/usr/local/bin/layerline --validate-config --config /etc/layerline/server.conf
/usr/local/bin/layerline --doctor --config /etc/layerline/server.conf
/usr/local/bin/layerline --certs --config /etc/layerline/server.conf
/usr/local/bin/layerline --admin-command status --config /etc/layerline/server.conf
/usr/local/bin/layerline --admin-command config --config /etc/layerline/server.conf
curl -fsS http://127.0.0.1:8080/health
curl -fsSI -H 'Accept-Encoding: gzip' http://127.0.0.1:8080/ | grep -i '^Content-Encoding: gzip'
printf 'status\n' | nc -U /run/layerline/admin.sock
printf 'validate\n' | nc -U /run/layerline/admin.sock
printf 'diff\n' | nc -U /run/layerline/admin.sock
printf 'config\n' | nc -U /run/layerline/admin.sock
printf 'cache-purge\n' | nc -U /run/layerline/admin.sock
printf 'certs\n' | nc -U /run/layerline/admin.sock
printf 'cert-renew\n' | nc -U /run/layerline/admin.sock
./scripts/benchmark-layerline.sh --verify-only --no-h3
```

For a local release candidate before copying files onto the host, run the self-starting verifier:

```bash
./scripts/verify-layerline.sh
```

For a binary built elsewhere, also cross-build the native child fixture for the
test host with `zig build test-tools -Dtarget=<target> -Doptimize=ReleaseFast`.
Pass absolute paths through `LAYERLINE_VERIFY_BINARY` and
`LAYERLINE_CHILD_WORKER` when running the verifier on that host. The helper is
test-only and is not needed on production listeners.

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
