# ClamAV

Headless, shell-free ClamAV container built on `mwaeckerlin/scratch`.
Runs `clamd` (the scanning daemon) as PID 1 and `freshclam --daemon`
as a child that auto-updates the virus database at the configured
interval. **No shell, no perl, no busybox, no package manager** in
the shipped image — same security posture as the sibling
`mwaeckerlin/redis` and `mwaeckerlin/rspamd`.

Intended primary use inside `mwaeckerlin/mailservice` as the
antivirus backend Rspamd talks to over TCP. Works standalone against
any consumer that speaks the clamd protocol on port 3310.

## Environment variables

| Variable              | Default                    | Description                                                                                                                                                                                             |
|-----------------------|----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `CLAMD_BIND`          | `0.0.0.0`                  | Interface(s) `clamd` binds to. Default is «all» because the container is meant to be reached from peer containers on the same Docker network.                                                          |
| `CLAMD_PORT`          | `3310`                     | clamd's TCP port (Rspamd's default).                                                                                                                                                                    |
| `CLAMD_MAX_FILESIZE`  | `2G`                       | clamd skips an individual file larger than this. Set to clamav's internal hard cap (2 GiB) — a single file above 2 GiB **cannot** be scanned by clamav and is skipped regardless of this value.          |
| `CLAMD_MAX_SCANSIZE`  | `4G`                       | Total per-message scan budget (across archive members). clamav's ceiling is ~4 GiB.                                                                                                                     |
| `CLAMD_STREAM_MAXLENGTH` | `4G`                    | Max size of an `INSTREAM` scan (the path Rspamd uses); clamav's ~4 GiB ceiling. clamd's own default is only 25 MB — it MUST be raised, otherwise clamd aborts the stream for larger mails.               |
| `FRESHCLAM_CHECKS`    | `24`                       | How many times per day `freshclam --daemon` checks for signature updates. `24` = hourly.                                                                                                                |
| `FRESHCLAM_MIRROR`    | `database.clamav.net`      | Upstream mirror for signature downloads. Override if you run a local mirror.                                                                                                                            |

### Configuration validation

Every value above is rendered into `clamd.conf`/`freshclam.conf`, which
are plain key-space-value files. To rule out config injection (a value
containing a newline would become an extra directive), `init` validates
each value before writing anything and **refuses to start** with a
clear `invalid <VAR>` error on a malformed value: the port must be
numeric (1–65535), `FRESHCLAM_CHECKS` numeric in freshclam's valid
range (1–50), sizes match `<digits>[K|M|G]`, bind address and mirror
are restricted to hostname/IP/URL characters (no whitespace). Pinned by
`tests/config-validation.sh`.

### Security posture of the clamd port

The clamd TCP protocol is **unauthenticated** — any peer that reaches
the port can submit scan jobs or issue administrative commands such as
`SHUTDOWN`. That is fine on an isolated Docker network among trusted
peer containers (the intended deployment, and the reason
`CLAMD_BIND=0.0.0.0` is an acceptable default), but the port must
**never** be published beyond that. The standalone smoke-test compose
file therefore binds it to `127.0.0.1` only.

`/etc/clamav` is owned by the `clamav` runtime user because `init`
(running as that user — the whole container is non-root) composes the
config files at start-up. Trade-off: a compromised scanner process
could rewrite its own config for the next start; accepted, since the
image has no shell to leverage and the alternative (root-owned config)
would require a root init.

### Behaviour when a mail exceeds these limits (fail-open)

Scanning is **fail-open by design** — the industry-standard choice for
a mail gateway: a scanner limit or outage must never bounce mail. A
message larger than clamav can scan is scanned up to the limit (or not
at all) and then **delivered**, never rejected.

The signalling is Rspamd's `CLAM_VIRUS_FAIL` symbol, which the antivirus
module raises on any scan error (size ceiling hit, clamd unreachable,
timeout). Its default weight is **0** (no score, no action) — this is
Rspamd's own convention and the recommended production setting: a virus
that clamav *can* scan is still rejected via `CLAM_VIRUS`, but an
un-scannable or oversized mail is delivered rather than lost. Consistent
with the mailservice rule «never reject a legitimate mail because of a
limit».

**Important:** clamav's scan sizes are hard architectural limits, not
freely raisable — a single file above 2 GiB and a message above ~4 GiB
simply cannot be scanned by clamav. `MESSAGE_SIZE_LIMIT` on `postfix`
(default 100 GiB) is deliberately far higher, so very large mails are
**accepted and delivered but not virus-scanned**. If that gap matters
for your deployment, cap `MESSAGE_SIZE_LIMIT` at what clamav can scan,
or add an out-of-band scanner for large files. There is no clamav
setting that scans a 100 GiB mail.

## First start: initial signature download

On a fresh install (empty `/var/lib/clamav` volume) `init` runs
`freshclam` once synchronously to bootstrap the ~200 MB virus
database. **This can take several minutes on first-ever start.**
Subsequent restarts skip the sync — the persisted volume already
has current signatures, and the background `freshclam --daemon`
keeps them refreshed. A downloaded update is activated immediately:
`freshclam` notifies `clamd` to reload (`NotifyClamd`); clamd's
hourly `SelfCheck` remains as fallback.

If the internet is unreachable during first start, `freshclam`
fails and `clamd` refuses to start (no DB to scan against). The
container will restart-loop. Fix by giving the container internet
access, or drop the DB into the volume from another source.

If the internet is unreachable *later*, background updates just
fail silently and `clamd` keeps scanning with the last good DB —
Marc's philosophy: never break a working component because a
non-critical update failed.

## Volumes to persist

- `/var/lib/clamav/` — the virus signature database (~200 MB).
  Non-critical: freshclam re-downloads on a fresh volume, but the
  initial bootstrap takes minutes. Persist to skip that pain on
  every container restart.

## Consumer integration (Rspamd)

Rspamd's `antivirus.conf` module talks to clamd over TCP:

    clamav {
        servers = "clamav:3310";
        symbol  = "CLAM_VIRUS";
        action  = "reject \"message rejected: virus detected (%s)\"";
    }

The `mwaeckerlin/rspamd` container ships this out of the box; set
`CLAMAV_HOST=clamav` on rspamd (which is the default when clamav
is the peer service in the same compose file).

## Image layout

Three-stage build, matching the `mwaeckerlin/nginx`,
`mwaeckerlin/php-fpm`, `mwaeckerlin/opendkim`,
`mwaeckerlin/opendmarc`, `mwaeckerlin/redis` and
`mwaeckerlin/rspamd` pattern:

1. **`init`** — compiles `init.cpp` statically with `g++ -static -Os
   -flto`. The resulting binary composes clamd + freshclam configs
   from env, bootstraps the DB if missing, spawns
   `freshclam --daemon` as a background child, then `execv`s
   `clamd --foreground` (which becomes PID 1).
2. **`build`** — installs `clamav`, `clamav-daemon`,
   `clamav-libunrar` and `ca-certificates` on the Alpine base, then
   uses `tar cph … + ldd` to collect only `clamd`, `freshclam`, the
   CA bundle (needed for the freshclam TLS handshake to
   `database.clamav.net`) and shared libraries into `/root/`.
3. **runtime** — `FROM mwaeckerlin/scratch`, `COPY --from=build
   /root/ /`. `ENTRYPOINT ["/usr/bin/init"]`.

Debugging on this shell-free image:

    docker compose logs clamav                 # both clamd and freshclam log here
    docker compose exec rspamd rspamc scan     # scan a message via rspamd + clamav

## Tests

    $ npm test

runs two suites against the locally built image:

1. `tests/image-contract.sh` — the image is headless: no `sh`, no
   `bash`, no `busybox`, no `perl` (same contract as the sibling
   images).
2. `tests/config-validation.sh` — malformed environment values are
   refused with a clear error instead of being rendered into the
   generated configs (config-injection guard); well-formed values
   pass.

The full mail flow including EICAR virus rejection through
postfix → rspamd → clamav is covered by the mailservice e2e suite
(`tests/e2e/test_virus_reject.py` in the parent repository).
