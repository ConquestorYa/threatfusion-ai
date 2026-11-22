FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

# The local API binds 127.0.0.1 only and has no host option (DEC-101, DEC-111).
# Run with `docker run --network host` so it is reachable on the host's own
# 127.0.0.1:8600; nothing is published to other machines.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src \
    THREATFUSION_PUBLIC_MODE=1

WORKDIR /app

RUN useradd --create-home --uid 10001 threatfusion

COPY requirements-runtime.txt ./
RUN python -m pip install --no-cache-dir -r requirements-runtime.txt

COPY . .

RUN mkdir -p /app/data /app/runtime \
    && chown -R threatfusion:threatfusion /app/data /app/runtime

USER threatfusion

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8600/api/health', timeout=3)"

CMD ["python", "-m", "threatfusion.api", "--port", "8600", "--static-dir", "/app/web/dist"]
