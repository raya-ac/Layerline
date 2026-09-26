"""Domain error regression checks against an isolated local Layerline process."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import time


def main():
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='layerline-errors-') as temp:
        root = pathlib.Path(temp)
        domains = root / 'domains'
        domains.mkdir()
        for name in ('branded', 'plain'):
            site = root / name
            site.mkdir()
            (site / 'index.html').write_text('a small static file')
            (domains / f'{name}.conf').write_text(f'name = {name}\nserver_name = {name}.test\nroot = {site}\nserve_static_root = true\nroute = down /down proxy\nroute_proxy.down = http://127.0.0.1:1\nroute_proxy_timeout_ms.down = 300\n')
        for code in range(400, 600):
            (root / 'branded' / f'{code}.html').write_text(f'<h1>branded error {code}</h1>')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        config = root / 'server.conf'
        config.write_text(f'host = 127.0.0.1\nport = {port}\ndir = {root / "plain"}\nserve_static_root = true\ndomain_config_dir = {domains}\n')
        with (root / 'server.log').open('w+') as log:
            process = subprocess.Popen([binary, '--config', str(config)], stdout=log, stderr=log)
            try:
                for _ in range(50):
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.2):
                            break
                    except OSError:
                        if process.poll() is not None:
                            log.seek(0)
                            raise RuntimeError(log.read())
                        time.sleep(.1)
                def fetch(protocol, path, host='branded.test', extra=()):
                    result = subprocess.run(['curl', protocol, '-sS', '--max-time', '5', '-D', str(root/'headers'), '-H', 'Host: '+host, *extra, f'http://127.0.0.1:{port}{path}'], check=True, capture_output=True)
                    headers = (root/'headers').read_text()
                    return int(headers.splitlines()[0].split()[1]), headers, result.stdout
                for protocol in ('--http1.1', '--http2-prior-knowledge'):
                    for path, code, extra in [('/missing', 404, ()), ('/index.html', 416, ('-H','Range: bytes=999999-')), ('/down', 502, ())]:
                        status, headers, body = fetch(protocol, path, extra=extra)
                        assert status == code, (protocol, path, status, body)
                        assert f'branded error {code}'.encode() in body, (protocol, path, body)
                        if code == 416:
                            assert 'content-range: bytes */' in headers.lower(), headers
                    status, _, body = fetch(protocol, '/missing', host='plain.test')
                    assert status == 404 and b'branded error' not in body
                    status, _, body = fetch(protocol, '/index.html')
                    assert status == 200 and body == b'a small static file'
                    status, headers, _ = fetch(protocol, '/missing', extra=('--head',))
                    assert status == 404 and 'content-length: 26' in headers.lower(), headers
                    print(protocol, '404 / 416 / 502 / HEAD / domain isolation passed', flush=True)
            finally:
                process.terminate()
                process.wait(timeout=5)


if __name__ == '__main__':
    main()
