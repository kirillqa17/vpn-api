FROM rust:latest AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

COPY . . # <--- Здесь копируются все файлы из корня репозитория
# Добавьте отладочные команды здесь
RUN ls -la # Показать, что было скопировано в /app
RUN cat Cargo.toml # Проверить, что Cargo.toml скопирован правильно

ARG DATABASE_URL
RUN echo "DEBUG: DATABASE_URL during build is: $DATABASE_URL" # Убедиться, что ARG передается
RUN cargo build --release --verbose # Более подробный вывод компиляции

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/vpn-api . # <--- Проверьте размер этого файла
RUN ls -la # Убедиться, что бинарник скопирован
RUN file ./vpn-api # Проверить тип бинарника (исполняемый ли он)

EXPOSE 8080

CMD ["./vpn-api"]