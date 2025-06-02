FROM rust:1.87-slim AS builder
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies
RUN cargo build --release && rm -rf src

# Copy actual source code
COPY src ./src

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    nmap \
    iputils-ping \
    net-tools \
    arp-scan \
    && rm -rf /var/lib/apt/lists/*

# Create app directory and user
RUN useradd -m -u 1001 appuser
WORKDIR /app

COPY --from=builder /app/target/release/luna_guard /app/
RUN chmod +x /app/luna_guard
RUN mkdir -p /data && chown appuser:appuser /data

USER appuser
EXPOSE 8080
CMD ["./luna_guard", "serve"]
