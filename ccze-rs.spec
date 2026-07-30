Name:           ccze-rs
Version:        0.4.0
Release:        1%{?dist}
Summary:        Streaming log colorizer with native analytics

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

%files
%license LICENSE
%doc README.md ARCHITECTURE.md
%{_bindir}/ccze
%{_mandir}/man1/ccze.1*

%changelog
* Thu Jul 30 2026 Kenny Glowner <SisyphusAeolides@pm.me> - 0.4.0-1
- Add streaming parsers, native analytics, and protocol verification
- Add Idris and Agda formal specifications
