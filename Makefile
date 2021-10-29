.PHONY: it

it:
	cargo fmt
	cargo clippy
	cargo doc --no-deps
	cargo test
	cargo run </dev/null
