Name:           ccze
Version:        0.3.0
Release:        %autorelease
Summary:        A robust, memory-safe log colorizer (Oxidized)

License:        GPL-2.0-or-later
URL:            https://github.com/SisyphusCode/ccze-rs
Source0:        %{url}/archive/v%{version}/ccze-rs-%{version}.tar.gz

BuildRequires:  rust-packaging
BuildRequires:  cargo

%description
CCZE is a robust and modular log colorizer. This package has been 
completely rewritten in Rust to provide memory safety, zero-copy string 
parsing, and extreme performance for bare-metal terminal environments.

%prep
%autosetup -n ccze-rs-%{version}
%cargo_prep

%generate_buildrequires
%cargo_generate_buildrequires

%build
%cargo_build

%install
%cargo_install

%files
%{_bindir}/ccze

%changelog
%autochangelog
