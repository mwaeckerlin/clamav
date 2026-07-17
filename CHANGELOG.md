# Changelog

- 2026-07-17 **1.0.0**
    - Initial release: headless, shell-free ClamAV container
        - runtime contains only the virus scanner, the signature updater and their libraries — no shell, no busybox, no perl, no package manager
        - built-in supervisor: on an empty volume the signature database is downloaded once before the scanner starts; afterwards the updater keeps running in the background on a configurable schedule
        - update failures never interrupt scanning — the scanner keeps working with the last good signature set
    - Configuration through environment variables (bind address, port, size limits, update frequency and mirror)
    - Container healthcheck probing the scanner port
    - Persist the signature-database volume to skip the large initial download on recreate; a lost volume is repopulated automatically
