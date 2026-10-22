# Multi-stage Dockerfile for Leakos with all secret scanning tools
FROM python:3.11-slim AS builder
ARG TARGETARCH

# Optional GitHub token for API rate limits
ARG GITHUB_TOKEN=""

# Install build dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    ca-certificates \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Build and install tools
WORKDIR /tmp

# Fetch all GitHub release versions in ONE step to minimize API calls
RUN AUTH_HEADER=""; \
    if [ -n "$GITHUB_TOKEN" ]; then AUTH_HEADER="Authorization: token $GITHUB_TOKEN"; fi && \
    echo "Fetching latest versions from GitHub..." && \
    GITLEAKS_VER=$(curl -sL -H "$AUTH_HEADER" https://api.github.com/repos/gitleaks/gitleaks/releases/latest | python3 -c "import sys, json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))") && \
    TRUFFLEHOG_VER=$(curl -sL -H "$AUTH_HEADER" https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | python3 -c "import sys, json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))") && \
    NOSEYPARKER_VER=$(curl -sL -H "$AUTH_HEADER" https://api.github.com/repos/praetorian-inc/noseyparker/releases/latest | python3 -c "import sys, json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))") && \
    KINGFISHER_VER=$(curl -sL -H "$AUTH_HEADER" https://api.github.com/repos/mongodb/kingfisher/releases/latest | python3 -c "import sys, json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))") && \
    REX_VER=$(curl -sL -H "$AUTH_HEADER" https://api.github.com/repos/JaimePolop/RExpository/releases/latest | python3 -c "import sys, json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))") && \
    echo "gitleaks: $GITLEAKS_VER" > /tmp/versions.txt && \
    echo "trufflehog: $TRUFFLEHOG_VER" >> /tmp/versions.txt && \
    echo "noseyparker: $NOSEYPARKER_VER" >> /tmp/versions.txt && \
    echo "kingfisher: $KINGFISHER_VER" >> /tmp/versions.txt && \
    echo "Rex: $REX_VER" >> /tmp/versions.txt && \
    cat /tmp/versions.txt

# Install gitleaks
RUN GITLEAKS_VER=$(grep gitleaks /tmp/versions.txt | cut -d' ' -f2) && \
    case "$TARGETARCH" in amd64) ASSET_ARCH=x64 ;; arm64) ASSET_ARCH=arm64 ;; *) exit 1 ;; esac && \
    echo "Installing gitleaks version: $GITLEAKS_VER" && \
    wget https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_linux_${ASSET_ARCH}.tar.gz && \
    tar -xzf gitleaks_${GITLEAKS_VER}_linux_${ASSET_ARCH}.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    chmod +x /usr/local/bin/gitleaks && \
    rm -f gitleaks_${GITLEAKS_VER}_linux_${ASSET_ARCH}.tar.gz

# Install trufflehog
RUN TRUFFLEHOG_VER=$(grep trufflehog /tmp/versions.txt | cut -d' ' -f2) && \
    case "$TARGETARCH" in amd64) ASSET_ARCH=amd64 ;; arm64) ASSET_ARCH=arm64 ;; *) exit 1 ;; esac && \
    echo "Installing trufflehog version: $TRUFFLEHOG_VER" && \
    wget https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VER}/trufflehog_${TRUFFLEHOG_VER}_linux_${ASSET_ARCH}.tar.gz && \
    tar -xzf trufflehog_${TRUFFLEHOG_VER}_linux_${ASSET_ARCH}.tar.gz && \
    mv trufflehog /usr/local/bin/ && \
    chmod +x /usr/local/bin/trufflehog && \
    rm -f trufflehog_${TRUFFLEHOG_VER}_linux_${ASSET_ARCH}.tar.gz

# Install the latest tagged Rex release for this CPU architecture.
RUN REX_VER=$(grep '^Rex:' /tmp/versions.txt | cut -d' ' -f2) && \
    wget -qO /usr/local/bin/Rex https://github.com/JaimePolop/RExpository/releases/download/v${REX_VER}/Rex-linux-${TARGETARCH} && \
    chmod +x /usr/local/bin/Rex

# Install noseyparker
RUN NOSEYPARKER_VER=$(grep noseyparker /tmp/versions.txt | cut -d' ' -f2) && \
    case "$TARGETARCH" in amd64) ASSET_ARCH=x86_64 ;; arm64) ASSET_ARCH=aarch64 ;; *) exit 1 ;; esac && \
    echo "Installing noseyparker version: $NOSEYPARKER_VER" && \
    wget https://github.com/praetorian-inc/noseyparker/releases/download/v${NOSEYPARKER_VER}/noseyparker-v${NOSEYPARKER_VER}-${ASSET_ARCH}-unknown-linux-musl.tar.gz && \
    tar -xzf noseyparker-v${NOSEYPARKER_VER}-${ASSET_ARCH}-unknown-linux-musl.tar.gz && \
    mv bin/noseyparker /usr/local/bin/ && \
    chmod +x /usr/local/bin/noseyparker && \
    rm -rf noseyparker-v${NOSEYPARKER_VER}-${ASSET_ARCH}-unknown-linux-musl.tar.gz bin share LICENSE

# Install kingfisher
RUN KINGFISHER_VER=$(grep kingfisher /tmp/versions.txt | cut -d' ' -f2) && \
    case "$TARGETARCH" in amd64) ASSET_ARCH=x64 ;; arm64) ASSET_ARCH=arm64 ;; *) exit 1 ;; esac && \
    echo "Installing kingfisher version: $KINGFISHER_VER" && \
    wget https://github.com/mongodb/kingfisher/releases/download/v${KINGFISHER_VER}/kingfisher-linux-${ASSET_ARCH}.tgz && \
    tar -xzf kingfisher-linux-${ASSET_ARCH}.tgz && \
    mv kingfisher /usr/local/bin/ && \
    chmod +x /usr/local/bin/kingfisher && \
    rm -f kingfisher-linux-${ASSET_ARCH}.tgz

# Final stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /usr/local/bin/gitleaks /usr/local/bin/
COPY --from=builder /usr/local/bin/trufflehog /usr/local/bin/
COPY --from=builder /usr/local/bin/Rex /usr/local/bin/
COPY --from=builder /usr/local/bin/noseyparker /usr/local/bin/
COPY --from=builder /usr/local/bin/kingfisher /usr/local/bin/
COPY --from=builder /tmp/versions.txt /leakos/scanner-versions.txt

# Set up working directory
WORKDIR /leakos

# Copy leakos files
COPY requirements.txt .
COPY leakos.py .
COPY README.md .
COPY LICENSE .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt ggshield \
    && ggshield --version

# Create a non-root user
RUN useradd -m -u 1000 leakos && \
    chown -R leakos:leakos /leakos

USER leakos

# Set entrypoint
ENTRYPOINT ["python", "/leakos/leakos.py"]
CMD ["--help"]
