Name:           ccze-rs
Version:        0.5.3
Release:        1%{?dist}
Summary:        Streaming log colorizer with native analytics

Provides:       ccze = %{version}-%{release}
Obsoletes:      ccze < %{version}-%{release}

License:        MIT
URL:            https://github.com/SisyphusAeolides/ccze-rs
Source0:        %{name}-%{version}.tar.gz
Source1:        vendor.tar.xz

BuildRequires:  cargo >= 1.75
BuildRequires:  gcc
BuildRequires:  gcc-gfortran
BuildRequires:  rust >= 1.75

%description
ccze-rs is a pipeline-friendly log colorizer with parsers for syslog,
web-server access logs, and JSON. It includes rolling anomaly detection through
a Fortran C ABI and formally specified protocol and severity reducers.

%prep
%autosetup -p1 -a 1
mkdir -p .cargo
mv cargo-config.toml .cargo/config.toml

%build
CCZE_FORCE_FORTRAN=1 CARGO_NET_OFFLINE=true CARGO_PROFILE_RELEASE_DEBUG=2 \
    CARGO_PROFILE_RELEASE_STRIP=false cargo build --frozen --release

%install
install -D -m 0755 target/release/ccze %{buildroot}%{_bindir}/ccze
install -D -m 0644 packaging/ccze.1 %{buildroot}%{_mandir}/man1/ccze.1

%check
CCZE_FORCE_FORTRAN=1 CARGO_NET_OFFLINE=true cargo test --frozen --all-targets
make packaging-check

%files
%license LICENSE
%doc README.md ARCHITECTURE.md
%{_bindir}/ccze
%{_mandir}/man1/ccze.1*

%changelog
* Sat Aug 08 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.5.3-1
- Add offline-buildable Ubuntu source packaging
- Declare the classic ccze package replacement relationship
- Preserve strict lint compatibility for the public library API

* Wed Aug 05 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.5.2-1
- Bound streamed log records to prevent unbounded memory growth

* Sat Aug 01 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.5.1-1
- Pin the test dependency graph to the declared Rust 1.75 baseline

* Sat Aug 01 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.5.0-1
- Add versioned metric-vector encoding and decoding
- Add opt-in Linux integration library APIs

* Thu Jul 30 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.4.0-1
- Add streaming parsers, native analytics, and protocol verification
- Add Idris and Agda formal specifications
