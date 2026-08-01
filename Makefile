.DEFAULT_GOAL := build

name := ccze-rs
version := 0.5.0
builddir := $(shell mktemp -d)

.PHONY: build check test proofs proofs-strict install tarball vendor srpm clean-dist

build:
	CCZE_FORCE_FORTRAN=1 cargo build --locked --release

check:
	cargo fmt --all -- --check
	cargo check --locked --all-targets
	cargo clippy --locked --all-targets -- -D warnings

test:
	CCZE_FORCE_FORTRAN=1 cargo test --locked --all-targets
	$(MAKE) proofs

proofs:
	sh scripts/check-formal.sh

proofs-strict:
	sh scripts/check-formal.sh --strict

install: build
	install -D -m 0755 target/release/ccze $(DESTDIR)$(PREFIX)/bin/ccze
	install -D -m 0644 packaging/ccze.1 $(DESTDIR)$(PREFIX)/share/man/man1/ccze.1

tarball:
	git archive --format=tar.gz --prefix=$(name)-$(version)/ --output=$(name)-$(version).tar.gz HEAD

vendor:
	cd $(builddir) && cargo vendor --locked --manifest-path=$(CURDIR)/Cargo.toml vendor > cargo-config.toml
	tar -C $(builddir) -cJf $(CURDIR)/vendor.tar.xz vendor cargo-config.toml

srpm:
	dnf -y install cargo rust git rpm-build gcc-gfortran make
	mkdir -p $(outdir)
	git archive --format=tar.gz --prefix=$(name)-$(version)/ --output=$(builddir)/$(name)-$(version).tar.gz HEAD
	cd $(builddir) && cargo vendor --locked --manifest-path=$(CURDIR)/Cargo.toml vendor > cargo-config.toml
	tar -C $(builddir) -cJf $(builddir)/vendor.tar.xz vendor cargo-config.toml
	rpmbuild -bs --define "_sourcedir $(builddir)" --define "_srcrpmdir $(outdir)" $(spec)

clean-dist:
	rm -f $(name)-$(version).tar.gz vendor.tar.xz
