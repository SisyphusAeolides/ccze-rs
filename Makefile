.DEFAULT_GOAL := build

name := ccze-rs
version := 0.5.3
builddir := $(shell mktemp -d)

.PHONY: build check test proofs proofs-strict packaging-check install tarball vendor srpm deb ppa-source ppa-source-unsigned clean-dist

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

packaging-check:
	grep -q '^Package: ccze-rs' debian/control
	grep -q '^Provides: ccze' debian/control
	grep -q '^Conflicts: ccze' debian/control
	grep -q '^Replaces: ccze' debian/control
	grep -q '^Provides:.*ccze' ccze-rs.spec
	grep -q '^Obsoletes:.*ccze' ccze-rs.spec
	test -x debian/rules
	test -x scripts/build-deb-source.sh
	test -f debian/ccze-rs.docs
	test -f packaging/ccze.1

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

deb:
	dpkg-buildpackage --build=binary --no-sign

ppa-source:
	sh scripts/build-deb-source.sh

ppa-source-unsigned:
	sh scripts/build-deb-source.sh --unsigned

clean-dist:
	rm -f $(name)-$(version).tar.gz vendor.tar.xz
