<div align="center">
  <img src="public/layerline-mark.svg" alt="layerline logo" width="104" height="104">
  <h1>layerline</h1>
  <p>a web server, written in zig.</p>
  <a href="https://layerline.dev">website</a> |
  <a href="docs/configuration.md">configuration</a> |
  <a href="docs/roadmap.md">roadmap</a>
</div>

i'm building layerline to run sites directly, without needing caddy or nginx in front of it.

it handles static files, php/fpm, reverse proxying and tls. there's native http/2, per-domain configs, caching, gzip, logs, metrics and an optional admin ui. http/3 is in the project too, but it's still experimental.

there's still work to do before i'd call it a drop-in caddy/nginx replacement. the [roadmap](docs/roadmap.md) and [security notes](docs/security.md) cover the gaps.

## run it

you'll need zig 0.16.

```sh
git clone https://github.com/raya-ac/Layerline.git
cd Layerline
zig build run -- --config examples/local.conf
```

open [localhost:8080](http://127.0.0.1:8080). for a release binary:

```sh
zig build -Doptimize=ReleaseFast
./zig-out/bin/layerline --config examples/local.conf
```

## config

keep the listener and process settings in `server.conf`, with a file per site in `domains-enabled/`. point `domain_config_dir` at that directory. cli flags override the config.

the [config guide](docs/configuration.md) has the examples for static sites, php, proxies, tls and reloads. the [deployment guide](docs/deployment.md) covers services and rollback.

## admin

the web ui is off by default. enabling it gives you site management, config editing and runtime controls on the same server. first-account setup needs a local token, so someone visiting an unconfigured server can't claim it. [setup and security details](docs/security.md#admin-access).

## tests

```sh
zig build test
./scripts/verify-layerline.sh
```

the verifier starts temporary local servers. [benchmarking](docs/benchmarking.md) is separate.

<p align="center">
  <img src="public/laina.png" alt="laina, layerline's mascot" width="160">
</p>
