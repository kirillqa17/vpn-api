FROM rust:latest AS builder

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