# Pin to bookworm so the builder's OpenSSL matches the runtime
# (debian:bookworm-slim has libssl3 from OpenSSL 3.0.x; rust:latest now
# tracks trixie/testing with OpenSSL 3.2+ which breaks the ABI).
FROM rust:bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
ARG DATABASE_URL
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/vpn-api .
COPY system_prompt.txt /app/system_prompt.txt
ENV SYSTEM_PROMPT_PATH=/app/system_prompt.txt

EXPOSE 8080

CMD ["./vpn-api"]