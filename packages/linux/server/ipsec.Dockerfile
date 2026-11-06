# Ghostlink IPsec component: strongSwan and iptables from Alpine, plus ghostlink-ipsec-agent.
# Built by scripts/build-linux-server.sh on each architecture's own runner. The final image holds
# only what the agent runs (no shell or package manager): charon, swanctl, the strongSwan plugins
# it loads, the iptables multi-binaries and their extensions, and the shared libraries these
# link. usr/share/doc/ghostlink-ipsec/packages.txt lists the Alpine packages those files come
# from; the release publishes the matching source (scripts/ipsec-source.sh).
FROM alpine:3.24.4@sha256:93b41ef40b1677fce8fcc64ff4af09daddfacf5040afde618bc46c1e2d1cc7d4 AS build
RUN apk add --no-cache strongswan iptables iptables-legacy
COPY collect.sh /collect.sh
RUN sh /collect.sh /out

FROM scratch
ARG VERSION
LABEL org.opencontainers.image.title="Ghostlink IPsec component" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="GPL-3.0-or-later AND GPL-2.0-or-later" \
      org.opencontainers.image.source="https://github.com/winyannainghtut/GHOSTLINK"
COPY --from=build /out/ /
COPY ghostlink-ipsec-agent /usr/bin/ghostlink-ipsec-agent
COPY licenses/ /usr/share/doc/ghostlink-ipsec/
ENV PATH=/usr/sbin:/usr/bin:/sbin:/bin
ENTRYPOINT ["/usr/bin/ghostlink-ipsec-agent"]
CMD ["serve"]
