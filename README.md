<div align="center">
  <img src="public/layerline-mark.svg" alt="layerline logo" width="104" height="104">
  <h1>layerline</h1>
  <p>a web server, written in zig.</p>
  <a href="https://layerline.dev">website</a> |
  <a href="docs/configuration.md">configuration</a> |
  <a href="docs/roadmap.md">roadmap</a>
</div>

i wanted one server i could put in front of my sites. that's what i'm building layerline for.

it serves static files, talks to PHP-FPM and proxies apps over HTTP or HTTPS. TLS and HTTP/2 are built in. there's a config file per site and a web admin you can leave off.

HTTP/3 works for the homepage and health check. i'd still leave it off in production. this isn't a drop-in caddy/nginx replacement yet. see the [roadmap](docs/roadmap.md) for what i'd finish before telling someone to switch.

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

the web ui is off by default. turn it on to add sites, stage config edits and reload. the first account needs a local setup token. [admin setup](docs/security.md#admin-access).

## tests

```sh
zig build test
./scripts/verify-layerline.sh
```

the verifier starts temporary local servers. GitHub runs the unit and wire checks on Linux and macOS, but doesn't deploy. [benchmarks](docs/benchmarking.md) are separate.

<p align="center">
  <img src="public/laina-v2.png" alt="laina, layerline's mascot" width="160">
</p>
