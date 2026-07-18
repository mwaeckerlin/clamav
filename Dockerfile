FROM mwaeckerlin/very-base AS init
RUN $PKG_INSTALL g++
COPY init.cpp .
RUN g++ -static -Os -flto=auto -fno-rtti -ffunction-sections -fdata-sections \
        -Wl,--gc-sections -Wl,-s -std=c++20 -o init init.cpp
RUN strip -s -R .comment -R .gnu.version --strip-unneeded init

FROM mwaeckerlin/very-base AS build
RUN $PKG_INSTALL clamav clamav-daemon clamav-libunrar ca-certificates
RUN mkdir -p /var/lib/clamav /etc/clamav /run/clamav /tmp \
    && chmod 1777 /tmp \
    && chown -R clamav:clamav /var/lib/clamav /etc/clamav /run/clamav
COPY --from=init init /usr/bin/init

# Collect only clamd + freshclam + shared libs + CA bundle (freshclam
# needs it to verify database.clamav.net TLS) into /root/. Runtime
# scratch stage carries nothing else — no shell, no perl, no busybox.
# Collect clamd + freshclam + their full shared-library closure.
# musl's `ldd` accepts exactly ONE file per invocation (it is the
# dynamic loader in --list mode), so the deps are gathered in a
# per-file loop — a multi-file `ldd a b` silently lists only `a`.
# The loop also covers libclamav/libfreshclam/libclamunrar, whose
# own deps (libcurl, libssl, libstdc++, …) do not appear in the
# binaries' ldd output. `/lib/ld-musl-x86_64.so.1` is listed
# explicitly: it is the ELF interpreter — without it every dynamic
# binary fails with a bare `No such file or directory`.
RUN tar cph \
        /var/lib/clamav /etc/clamav /run/clamav /tmp \
        /etc/passwd /etc/group /etc/nsswitch.conf \
        /etc/ssl/certs /etc/ssl/cert.pem /usr/share/ca-certificates \
        /usr/sbin/clamd /usr/bin/freshclam /usr/bin/init \
        /lib/ld-musl-x86_64.so.1 \
        /usr/lib/libclamav.so* /usr/lib/libfreshclam.so* \
        /usr/lib/libclamunrar*.so* \
        $(for f in /usr/sbin/clamd /usr/bin/freshclam \
                   /usr/lib/libclamav.so.* /usr/lib/libfreshclam.so.* \
                   /usr/lib/libclamunrar*.so.*; do \
              ldd "$f" 2>/dev/null | sed -n 's,.* => \([^ ]*\) .*,\1,p'; \
          done | sort -u) \
    | tar xpC /root/

FROM mwaeckerlin/scratch
ENV CONTAINERNAME="clamav" \
    CLAMD_BIND="0.0.0.0" \
    CLAMD_PORT="3310" \
    CLAMD_MAX_FILESIZE="2G" \
    CLAMD_MAX_SCANSIZE="4G" \
    CLAMD_STREAM_MAXLENGTH="4G" \
    FRESHCLAM_CHECKS="24" \
    FRESHCLAM_MIRROR="database.clamav.net"
EXPOSE 3310
VOLUME /var/lib/clamav
USER clamav
ENTRYPOINT ["/usr/bin/init"]
COPY --from=build /root/ /
