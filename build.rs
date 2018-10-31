// build.rs

use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    Command::new("gcc").args(&["aez_amd64_aesni_c/encrypt.c", "-g", "-O0",
                               "-Wall", "-msse2", "-march=native", "-maes",
                               "-fPIC", "-c", "-o"])
                       .arg(&format!("{}/fast_aez.o", out_dir))
                       .status().unwrap();
    Command::new("ar").args(&["crs", "libaez.a", "fast_aez.o"])
                      .current_dir(&Path::new(&out_dir))
                      .status().unwrap();
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=aez");
}
