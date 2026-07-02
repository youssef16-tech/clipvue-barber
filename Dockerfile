# ---- build stage ----
# Debian (glibc) + cmake: reliably compiles bundled SQLite and rustls 0.23's
# aws-lc-rs, which are both painful on musl/alpine. Pinned to a recent Rust
# because several transitive deps (icu/time) need a modern compiler.
FROM rust:1-bookworm AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake build-essential pkg-config perl && rm -rf /var/lib/apt/lists/*
# Cache dependencies first for faster rebuilds.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src
COPY . .
RUN touch src/main.rs && cargo build --release

# ---- runtime stage ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/clipvue-barber /app/clipvue-barber
COPY static /app/static
EXPOSE 8080
CMD ["/app/clipvue-barber"]
