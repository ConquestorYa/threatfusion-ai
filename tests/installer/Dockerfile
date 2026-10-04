ARG DISTRIBUTION=debian:bookworm-slim
FROM ${DISTRIBUTION}
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl wget tar coreutils util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 installer
USER installer
WORKDIR /home/installer
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["bash"]
