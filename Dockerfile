FROM rust:latest AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

COPY . .
# Добавьте отладочные команды здесь
RUN ls -la 
RUN cat Cargo.toml 
RUN cat src/main.rs

ARG DATABASE_URL
RUN echo "DEBUG: DATABASE_URL during build is: $DATABASE_URL" 
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/vpn-api . 
RUN ls -la 

EXPOSE 8080

CMD ["./vpn-api"]