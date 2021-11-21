.PHONY: it

it:
	cargo fmt
	cargo clippy
	cargo doc --no-deps
	cargo test
	cargo run --bin dochtml
	cargo run </dev/null

upload:
	git push --follow-tags all
	git remote update
	rsync -ia --del --exclude '*~' doc/ \
		fanf@dotat.at:public-html/prog/ssh-box/
