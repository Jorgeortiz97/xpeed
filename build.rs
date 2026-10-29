use std::{env, path::PathBuf, process::Command};

fn clang() -> String {
    env::var("CLANG").unwrap_or_else(|_| {
        ["clang", "clang-21", "clang-20", "clang-19", "clang-18"]
            .into_iter()
            .find(|c| Command::new(c).arg("--version").output().is_ok_and(|o| o.status.success()))
            .expect("clang not found; set CLANG")
            .into()
    })
}

fn main() {
    println!("cargo:rerun-if-changed=src/bpf");
    println!("cargo:rerun-if-env-changed=CLANG");
    println!("cargo:rerun-if-env-changed=DEB_HOST_MULTIARCH");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    // <linux/types.h> pulls <asm/types.h> from the Debian multiarch include dir.
    // Defaults to the build machine's headers: the BPF objects only depend on
    // the target's endianness, so cross and musl builds can use them as well.
    let multiarch = env::var("DEB_HOST_MULTIARCH")
        .unwrap_or_else(|_| env::var("HOST").unwrap().replace("-unknown-", "-"));
    let target = match env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() {
        Ok("big") => "bpfeb",
        _ => "bpfel",
    };
    let clang = clang();
    // v3's 32-bit ALU trims xpeed_tx's per-packet path, and the client needs
    // Linux >= 5.18 anyway; xpeed_rx gains nothing and stays loadable anywhere.
    for (name, cpu) in [("tx", "v3"), ("rx", "v1")] {
        let status = Command::new(&clang)
            .args(["-O2", "-g", "-Wall", "-Werror", "-target", target, "-c"])
            .arg(format!("-mcpu={cpu}"))
            .arg(format!("-I/usr/include/{multiarch}"))
            .arg(format!("src/bpf/{name}.bpf.c"))
            .arg("-o")
            .arg(out.join(format!("{name}.bpf.o")))
            .status()
            .expect("failed to run clang");
        assert!(status.success(), "clang failed to build {name}.bpf.c");
    }
}
