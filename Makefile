lint:
	typos
	cargo clippy --all-targets --all -- --deny=warnings

dev:
	cargo run --bin httpstat -- https://www.cloudflare.com/

bloat:
	cargo bloat --release --crates

fmt:
	cargo fmt

outdated:
	cargo outdated

test:
	cargo test

msrv:
	cargo msrv list

release:
	cargo build --release