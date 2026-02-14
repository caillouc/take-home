# ── Build stage ──────────────────────────────────────────────────
FROM rust:1.88 AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY tests/ tests/

RUN cargo build --release

# ── Runtime stage ────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/take-home /usr/local/bin/take-home

ENV PORT=3000

EXPOSE 3000

CMD ["take-home"]
