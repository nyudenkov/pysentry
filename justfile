done: fmt-check clippy test

fmt-check:
    cargo fmt --all -- --check

fmt:
    cargo fmt --all

clippy:
    cargo clippy --all-targets --all-features -- -D warnings

test:
    cargo test
