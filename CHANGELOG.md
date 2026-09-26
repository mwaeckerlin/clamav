# Changelog

- 2026-09-26 **3.5.1**
    - The image builds on arm64 as well as on amd64 and is published for both under one tag, built and published automatically on every change and every week

- 2026-07-18 **1.0.1**
    - Security hardening after static security review
        - all configuration values from the environment are validated before use; a malformed value (port, update frequency, size limit, bind address or mirror) stops the container with a clear error instead of silently ending up in the scanner configuration
        - the standalone smoke-test setup now exposes the scanner port on localhost only — the scanner protocol is unauthenticated and must never be reachable from outside the machine
        - the standalone smoke-test setup reports container health via the built-in probe, same as the full mailservice test stack
    - New virus signatures become active immediately after download instead of up to an hour later
    - Project-local test suite: headless-image contract and configuration validation (`npm test`)
    - Documentation: security posture of the scanner port, configuration validation and test instructions

- 2026-07-17 **1.0.0**
    - Initial release: headless, shell-free ClamAV container
        - runtime contains only the virus scanner, the signature updater and their libraries — no shell, no busybox, no perl, no package manager
        - built-in supervisor: on an empty volume the signature database is downloaded once before the scanner starts; afterwards the updater keeps running in the background on a configurable schedule
        - update failures never interrupt scanning — the scanner keeps working with the last good signature set
    - Configuration through environment variables (bind address, port, size limits, update frequency and mirror)
    - Container healthcheck probing the scanner port
    - Persist the signature-database volume to skip the large initial download on recreate; a lost volume is repopulated automatically
