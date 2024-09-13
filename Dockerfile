# Build stage
FROM rust:1.81.0 as builder

# Install necessary tools and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    llvm \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --component rust-src
RUN cargo install bpf-linker

# Set the working directory
WORKDIR /usr/src/build/

ADD .. ./

RUN cargo xtask build --release

# Final image stage
FROM debian:buster-slim

# Install necessary dependencies
RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the built binary from the build stage
COPY --from=builder /usr/src/build/target/release/traffic-billing /usr/local/bin/traffic-billing

# Set the working directory
WORKDIR /app

# Run the application
CMD ["traffic-billing"]