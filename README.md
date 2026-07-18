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
| `CLAMD_MAX_FILESIZE`  | `1G`                       | clamd stops scanning an individual file larger than this. Kept very high (1 GiB) so normal large attachments are actually scanned; a low value would silently leave them unscanned. Configurable.       |
| `CLAMD_MAX_SCANSIZE`  | `1G`                       | Total per-message scan budget. Same rationale — very high default, configurable.                                                                                                                        |
| `CLAMD_STREAM_MAXLENGTH` | `1G`                    | Max size of an `INSTREAM` scan (the path Rspamd uses). clamd's own default is only 25 MB — it MUST be raised to match the sizes above, otherwise clamd aborts the stream for larger mails.               |
| `FRESHCLAM_CHECKS`    | `24`                       | How many times per day `freshclam --daemon` checks for signature updates. `24` = hourly.                                                                                                                |
| `FRESHCLAM_MIRROR`    | `database.clamav.net`      | Upstream mirror for signature downloads. Override if you run a local mirror.                                                                                                                            |

### Behaviour when a mail exceeds these limits

Scanning is **fail-open by design**: a message larger than the limits
above is scanned only up to the limit (or not at all) and then
**delivered**, never bounced. Rspamd's antivirus module reports a
`CLAM_VIRUS_FAIL` symbol (weight 0, no action) on a scan error, so an
oversized or unscannable mail is delivered rather than rejected —
consistent with the mailservice rule «never reject a legitimate mail
because of a limit». Raise the limits (they default to 1 GiB) if
you want even larger mails fully scanned; a virus that fits inside the
scan budget is still rejected as normal.

## First start: initial signature download

On a fresh install (empty `/var/lib/clamav` volume) `init` runs
`freshclam` once synchronously to bootstrap the ~200 MB virus
database. **This can take several minutes on first-ever start.**
Subsequent restarts skip the sync — the persisted volume already
has current signatures, and the background `freshclam --daemon`
keeps them refreshed.

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
