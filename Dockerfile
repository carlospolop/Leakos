# Multi-stage Dockerfile for Leakos with all secret scanning tools
FROM python:3.11-slim as builder

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

    # Install Go (needed for some tools) - fetch latest stable version
    RUN LATEST_GO=$(curl -sL 'https://go.dev/dl/?mode=json' | python3 -c "import sys, json; print(json.load(sys.stdin)[0]['version'])") && \
    echo "Installing Go version: $LATEST_GO" && \
    wget https://go.dev/dl/${LATEST_GO}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf ${LATEST_GO}.linux-amd64.tar.gz && \
    rm ${LATEST_GO}.linux-amd64.tar.gz
    
    ENV PATH="/usr/local/go/bin:${PATH}"
    ENV GOPATH="/go"
    ENV PATH="${GOPATH}/bin:${PATH}"

# Install Rust (needed for noseyparker and kingfisher)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

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
    echo "gitleaks: $GITLEAKS_VER" > /tmp/versions.txt && \
    echo "trufflehog: $TRUFFLEHOG_VER" >> /tmp/versions.txt && \
    echo "noseyparker: $NOSEYPARKER_VER" >> /tmp/versions.txt && \
    echo "kingfisher: $KINGFISHER_VER" >> /tmp/versions.txt && \
    cat /tmp/versions.txt

# Install gitleaks
RUN GITLEAKS_VER=$(grep gitleaks /tmp/versions.txt | cut -d' ' -f2) && \
    echo "Installing gitleaks version: $GITLEAKS_VER" && \
    wget https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_linux_x64.tar.gz && \
    tar -xzf gitleaks_${GITLEAKS_VER}_linux_x64.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    chmod +x /usr/local/bin/gitleaks && \
    rm -f gitleaks_${GITLEAKS_VER}_linux_x64.tar.gz

# Install trufflehog
RUN TRUFFLEHOG_VER=$(grep trufflehog /tmp/versions.txt | cut -d' ' -f2) && \
    echo "Installing trufflehog version: $TRUFFLEHOG_VER" && \
    wget https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VER}/trufflehog_${TRUFFLEHOG_VER}_linux_amd64.tar.gz && \
    tar -xzf trufflehog_${TRUFFLEHOG_VER}_linux_amd64.tar.gz && \
    mv trufflehog /usr/local/bin/ && \
    chmod +x /usr/local/bin/trufflehog && \
    rm -f trufflehog_${TRUFFLEHOG_VER}_linux_amd64.tar.gz

# Install Rex - clone and build from source
RUN echo "Installing Rex (latest from GitHub)" && \
    git clone --depth 1 https://github.com/JaimePolop/RExpository.git /tmp/RExpository && \
    cd /tmp/RExpository/clients/go && \
    go build -o Rex regexFinder.go && \
    mv Rex /usr/local/bin/ && \
    chmod +x /usr/local/bin/Rex && \
    rm -rf /tmp/RExpository

# Install noseyparker
RUN NOSEYPARKER_VER=$(grep noseyparker /tmp/versions.txt | cut -d' ' -f2) && \
    echo "Installing noseyparker version: $NOSEYPARKER_VER" && \
    wget https://github.com/praetorian-inc/noseyparker/releases/download/v${NOSEYPARKER_VER}/noseyparker-v${NOSEYPARKER_VER}-x86_64-unknown-linux-musl.tar.gz && \
    tar -xzf noseyparker-v${NOSEYPARKER_VER}-x86_64-unknown-linux-musl.tar.gz && \
    mv bin/noseyparker /usr/local/bin/ && \
    chmod +x /usr/local/bin/noseyparker && \
    rm -rf noseyparker-v${NOSEYPARKER_VER}-x86_64-unknown-linux-musl.tar.gz bin share LICENSE

# Install kingfisher
RUN KINGFISHER_VER=$(grep kingfisher /tmp/versions.txt | cut -d' ' -f2) && \
    echo "Installing kingfisher version: $KINGFISHER_VER" && \
    wget https://github.com/mongodb/kingfisher/releases/download/v${KINGFISHER_VER}/kingfisher-linux-x64.tgz && \
    tar -xzf kingfisher-linux-x64.tgz && \
    mv kingfisher /usr/local/bin/ && \
    chmod +x /usr/local/bin/kingfisher && \
    rm -f kingfisher-linux-x64.tgz

# Install ggshield (Python tool) - always get latest
RUN echo "Installing ggshield (latest from PyPI)" && \
    pip install --no-cache-dir ggshield

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
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/ggshield /usr/local/bin/

# Set up working directory
WORKDIR /leakos

# Copy leakos files
COPY requirements.txt .
COPY leakos.py .
COPY README.md .
COPY LICENSE .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create a non-root user
RUN useradd -m -u 1000 leakos && \
    chown -R leakos:leakos /leakos

USER leakos

# Set entrypoint
ENTRYPOINT ["python", "/leakos/leakos.py"]
CMD ["--help"]
