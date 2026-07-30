use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=CCZE_FORCE_FORTRAN");
    println!("cargo:rerun-if-changed=native/fortran/analytics.f90");
    println!("cargo:rerun-if-changed=native/fortran/analytics_fallback.c");
    println!("cargo:rerun-if-changed=native/idris/protocol.c");
    println!("cargo:rerun-if-changed=native/agda/severity.c");

    cc::Build::new()
        .file("native/idris/protocol.c")
        .file("native/agda/severity.c")
        .warnings(true)
        .compile("ccze_verified");

    if compile_fortran() {
        println!("cargo:rustc-env=CCZE_ANALYTICS_BACKEND=fortran");
    } else {
        assert!(
            env::var_os("CCZE_FORCE_FORTRAN").is_none(),
            "CCZE_FORCE_FORTRAN is set, but gfortran could not compile the analytics engine"
        );
        println!("cargo:warning=gfortran unavailable; using the portable analytics implementation");
        cc::Build::new()
            .file("native/fortran/analytics_fallback.c")
            .warnings(true)
            .compile("ccze_analytics");
        println!("cargo:rustc-env=CCZE_ANALYTICS_BACKEND=portable-c");
    }
}

fn compile_fortran() -> bool {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let object = out_dir.join("analytics.o");
    let library = out_dir.join("libccze_analytics.a");

    let compiled = Command::new("gfortran")
        .args(["-O3", "-fPIC", "-c", "native/fortran/analytics.f90", "-J"])
        .arg(&out_dir)
        .arg("-o")
        .arg(&object)
        .status()
        .is_ok_and(|status| status.success());
    if !compiled {
        return false;
    }

    if !archive(&library, &object) {
        return false;
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=ccze_analytics");
    println!("cargo:rustc-link-lib=gfortran");
    true
}

fn archive(library: &Path, object: &Path) -> bool {
    Command::new("ar")
        .arg("crus")
        .arg(library)
        .arg(object)
        .status()
        .is_ok_and(|status| status.success())
}
