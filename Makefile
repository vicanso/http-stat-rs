lint:
	typos
	cargo clippy --all-targets --all -- --deny=warnings

bloat:
	cargo bloat --release --crates

outdated:
	cargo outdated

test:
	cargo test

msrv:
	cargo msrv list

release:
	cargo build --release