# Ghostlink server image. Built by scripts/build-linux-server.sh on each architecture's own
# runner; there are no RUN steps, so no emulation is needed. The image is shipped inside the
# ghostlink-server .deb/.rpm and never pushed to a registry.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG VERSION
LABEL org.opencontainers.image.title="Ghostlink server" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/winyannainghtut/GHOSTLINK"
COPY ghostlink-server /usr/bin/ghostlink-server
COPY licenses/ /usr/share/doc/ghostlink-server/
USER 65532:65532
ENTRYPOINT ["/usr/bin/ghostlink-server"]
CMD ["serve"]
