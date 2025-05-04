lint:
	typos
	cargo clippy --all-targets --all -- --deny=warnings


bloat:
	cargo bloat --release --crates

outdated:
	cargo outdated

msrv:
	cargo msrv list

release:
	cargo build --release