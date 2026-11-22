# Opengrep rule sources

Bundled so the default scanner works locally and in Docker without downloading rules.

- `security-audit.yaml`: <https://semgrep.dev/c/p/security-audit>, fetched 2026-11-20.
- `owasp-top-ten.yaml`: <https://semgrep.dev/c/p/owasp-top-ten>, fetched 2026-11-20.
- `php/`: 24 selected files from <https://github.com/opengrep/opengrep-rules>, commit `f1d2b562b414783763fd02a6ed2736eaed622efa`.

The PHP selection matches the former Dockerfile list: Symfony, Laravel, Doctrine,
file inclusion, SSRF, deserialization, eval/exec and related PHP security rules.
