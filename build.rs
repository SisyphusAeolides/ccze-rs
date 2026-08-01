use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=CCZE_FORCE_FORTRAN");
    for source in [
        "native/fortran/analytics.f90",
        "native/fortran/analytics_fallback.c",
        "native/fortran/vector_encoder.f90",
        "native/fortran/vector_encoder_fallback.c",
        "native/idris/protocol.c",
        "native/agda/severity.c",
        "native/agda/vector.c",
    ] {
        println!("cargo:rerun-if-changed={source}");
    }

    cc::Build::new()
        .file("native/idris/protocol.c")
        .file("native/agda/severity.c")
        .file("native/agda/vector.c")
        .warnings(true)
        .compile("ccze_verified");

    let analytics_fortran = compile_fortran("native/fortran/analytics.f90", "ccze_analytics");
    let vector_fortran =
        compile_fortran("native/fortran/vector_encoder.f90", "ccze_vector_encoder");
    if analytics_fortran && vector_fortran {
        let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
        println!("cargo:rustc-link-search=native={}", out_dir.display());
        println!("cargo:rustc-link-lib=static=ccze_analytics");
        println!("cargo:rustc-link-lib=static=ccze_vector_encoder");
        println!("cargo:rustc-link-lib=gfortran");
        println!("cargo:rustc-env=CCZE_ANALYTICS_BACKEND=fortran");
        println!("cargo:rustc-env=CCZE_VECTOR_BACKEND=fortran");
    } else {
        assert!(
            env::var_os("CCZE_FORCE_FORTRAN").is_none(),
            "CCZE_FORCE_FORTRAN is set, but gfortran could not compile every Fortran backend"
        );
        println!("cargo:warning=using portable C analytics and vector implementations");
        cc::Build::new()
            .file("native/fortran/analytics_fallback.c")
            .file("native/fortran/vector_encoder_fallback.c")
            .warnings(true)
            .compile("ccze_portable");
        println!("cargo:rustc-env=CCZE_ANALYTICS_BACKEND=portable-c");
        println!("cargo:rustc-env=CCZE_VECTOR_BACKEND=portable-c");
    }

    if env::var_os("CARGO_FEATURE_SYSTEM_INTEGRATION").is_some() {
        compile_system_integration();
    }
}

fn compile_fortran(source: &str, stem: &str) -> bool {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let object = out_dir.join(format!("{stem}.o"));
    let library = out_dir.join(format!("lib{stem}.a"));

    let compiled = Command::new("gfortran")
        .args(["-O3", "-fPIC", "-c", source, "-J"])
        .arg(&out_dir)
        .arg("-o")
        .arg(&object)
        .status()
        .is_ok_and(|status| status.success());
    if !compiled || !archive(&library, &object) {
        return false;
    }

    true
}

fn compile_system_integration() {
    let sources = ["native/lsm/lsm_operations.c"];
    for source in sources {
        println!("cargo:rerun-if-changed={source}");
    }
    let mut build = cc::Build::new();
    for source in sources {
        build.file(source);
    }
    build.warnings(true).compile("ccze_system_integration");
}

fn archive(library: &Path, object: &Path) -> bool {
    Command::new("ar")
        .arg("crus")
        .arg(library)
        .arg(object)
        .status()
        .is_ok_and(|status| status.success())
}
