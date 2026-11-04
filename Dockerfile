# AutoPatch — run the agent itself inside a container so that verifying
# untrusted repos (their test suites execute code) happens behind a real
# isolation boundary, on top of the sandbox's temp-copy + env scrub.
#
#   docker build -t autopatch .
#   docker run --rm --network none -v "$PWD/target:/repo" \
#     -e META_API_KEY autopatch run --repo /repo --alerts /repo/alerts.json
#
# Note: --network none blocks the Meta API too; drop it (or allowlist the
# API host) for live LLM runs. The sandbox always strips secrets from the
# environment of repo test processes.
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/autopatch
COPY pyproject.toml README.md ./
COPY autopatch ./autopatch
RUN pip install --no-cache-dir . pytest semgrep

RUN useradd --create-home autopatch
USER autopatch

ENTRYPOINT ["autopatch"]
CMD ["--help"]
