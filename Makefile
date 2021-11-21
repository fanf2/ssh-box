.PHONY: it

it:
	cargo fmt
	cargo clippy
	cargo doc --no-deps
	cargo test
	cargo run --bin ssh-box-html
	cargo run </dev/null
