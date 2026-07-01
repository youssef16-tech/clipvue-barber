FROM rust:1.77-alpine AS builder
WORKDIR /app
COPY . .
RUN apk add --no-cache musl-dev pkgconfig openssl-dev perl
RUN cargo build --release

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/target/release/clipvue-barber /app/clipvue-barber
COPY static /app/static
ENV PORT=8080
EXPOSE 8080
CMD ["/app/clipvue-barber"]
