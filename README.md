# nginx-config-auditor

A small, free, stdlib-only Python 3 static analyzer for nginx configuration
files. No network calls, no dependencies, read-only. Point it at a config
file, a directory of `.conf` files, or a running Docker container and it
flags common misconfigurations:

- `autoindex on` (directory listing exposure) — HIGH
- weak TLS protocols (SSLv2/3, TLSv1, TLSv1.1) in `ssl_protocols` — HIGH
- weak cipher tokens (RC4, DES, 3DES, MD5, EXPORT, NULL, ADH, PSK) in `ssl_ciphers` — HIGH
- `root` / `alias` pointing at `/` — MEDIUM
- missing common security headers (HSTS, X-Content-Type-Options,
  X-Frame-Options, CSP, Referrer-Policy) — MEDIUM
- `server_tokens` left on/default (version disclosure) — LOW
- `ssl_prefer_server_ciphers off` — LOW
- missing `ssl_dhparam` — LOW
- informational notes: plaintext `proxy_pass` backends, SSI enabled,
  `auth_basic_user_file` presence, HTTP/2 not enabled on SSL listeners

## Usage

```
python3 nginx_config_auditor.py /etc/nginx/nginx.conf
python3 nginx_config_auditor.py /etc/nginx/                 # recursive *.conf scan
python3 nginx_config_auditor.py --docker my-nginx-container # docker cp's /etc/nginx out and scans it
python3 nginx_config_auditor.py /etc/nginx/ --json          # machine-readable output
python3 nginx_config_auditor.py /etc/nginx/ --min-severity HIGH  # only show HIGH findings
```

Exit code is `1` if any HIGH-severity finding exists (useful in CI), `0` otherwise.

## Known limitations (be honest about these)

- This is a **static** analyzer of individual config files, not a live
  merged-config walker. If a directive (e.g. security headers, ssl_protocols)
  is set in a different `include`d file than the one you point it at, you'll
  get a false "missing" finding — always re-check with `nginx -T` for the
  fully merged config if you want to be sure.
- Comment-stripping is a simple `#`-to-end-of-line strip; it does not handle
  `#` inside quoted strings (nginx configs rarely need this, but it's a real
  limitation).
- It flags patterns, it does not prove exploitability — every HIGH/MEDIUM
  finding is worth a human look, not an automatic "fix this now."

## Real example run

Run against the production `errant-solutions` nginx container (this site,
errant.solutions, TLS-terminated upstream by a reverse proxy so ssl_* config
lives elsewhere — correctly reported as INFO, not a false HIGH):

```
$ python3 nginx_config_auditor.py --docker errant-solutions
nginx-config-auditor: scanned 3 file(s), 21 finding(s)

[MEDIUM] missing_header           .../conf.d/default.conf
         no add_header for Strict-Transport-Security found in this file (...)
[MEDIUM] missing_header           .../conf.d/default.conf
         no add_header for X-Content-Type-Options found in this file (...)
... (5 missing-header findings x 3 files = 15)
[LOW   ] server_tokens_default    .../conf.d/default.conf
         server_tokens not set explicitly -- nginx defaults to 'on' (...)
... (3 files)
[INFO  ] ssl_protocols_unset      .../conf.d/default.conf
         no explicit ssl_protocols directive found in this file (...)
... (3 files)
```

Unedited real output. Took action on it: added the 5 missing security
headers to this very site's nginx config as part of shipping this tool
(see errant.solutions blog post for the diff).

## Pay what you want

Free to use, no license restrictions (MIT). If it saved you time, a
pay-what-you-want tip is appreciated but never required:
https://buy.stripe.com/PLACEHOLDER

## License

MIT
