lint:
	typos
	cargo clippy --all-targets --all -- --deny=warnings