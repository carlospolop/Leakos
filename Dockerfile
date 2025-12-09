# Multi-stage Dockerfile for Leakos with all secret scanning tools
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    ca-certificates \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Go (needed for some tools) - fetch latest stable version
RUN LATEST_GO=$(curl -sL 'https://go.dev/dl/?mode=json' | grep -oP '"version":"\K[^"]+' | head -1) && \
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

# Install gitleaks - fetch latest release
RUN LATEST_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    wget https://github.com/gitleaks/gitleaks/releases/download/v${LATEST_VERSION}/gitleaks_${LATEST_VERSION}_linux_x64.tar.gz && \
    tar -xzf gitleaks_${LATEST_VERSION}_linux_x64.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    chmod +x /usr/local/bin/gitleaks && \
    rm -f gitleaks_${LATEST_VERSION}_linux_x64.tar.gz

# Install trufflehog - fetch latest release
RUN LATEST_VERSION=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    wget https://github.com/trufflesecurity/trufflehog/releases/download/v${LATEST_VERSION}/trufflehog_${LATEST_VERSION}_linux_amd64.tar.gz && \
    tar -xzf trufflehog_${LATEST_VERSION}_linux_amd64.tar.gz && \
    mv trufflehog /usr/local/bin/ && \
    chmod +x /usr/local/bin/trufflehog && \
    rm -f trufflehog_${LATEST_VERSION}_linux_amd64.tar.gz

# Install Rex - always get latest from Go
RUN go install github.com/JaimePolop/RExpository@latest && \
    cp /go/bin/RExpository /usr/local/bin/Rex

# Install noseyparker - fetch latest release
RUN LATEST_VERSION=$(curl -s https://api.github.com/repos/praetorian-inc/noseyparker/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    wget https://github.com/praetorian-inc/noseyparker/releases/download/v${LATEST_VERSION}/noseyparker-v${LATEST_VERSION}-x86_64-unknown-linux-musl.tar.gz && \
    tar -xzf noseyparker-v${LATEST_VERSION}-x86_64-unknown-linux-musl.tar.gz && \
    mv noseyparker-v${LATEST_VERSION}-x86_64-unknown-linux-musl/bin/noseyparker /usr/local/bin/ && \
    chmod +x /usr/local/bin/noseyparker && \
    rm -rf noseyparker-v${LATEST_VERSION}-x86_64-unknown-linux-musl*

# Install kingfisher - fetch latest release
RUN LATEST_VERSION=$(curl -s https://api.github.com/repos/mongodb/kingfisher/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    wget https://github.com/mongodb/kingfisher/releases/download/v${LATEST_VERSION}/kingfisher-v${LATEST_VERSION}-x86_64-unknown-linux-musl.tar.gz && \
    tar -xzf kingfisher-v${LATEST_VERSION}-x86_64-unknown-linux-musl.tar.gz && \
    mv kingfisher-v${LATEST_VERSION}-x86_64-unknown-linux-musl/kingfisher /usr/local/bin/ && \
    chmod +x /usr/local/bin/kingfisher && \
    rm -rf kingfisher-v${LATEST_VERSION}-x86_64-unknown-linux-musl*

# Install ggshield (Python tool) - always get latest
RUN pip install --no-cache-dir ggshield

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
