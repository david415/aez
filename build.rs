// build.rs

use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    Command::new("gcc").args(&["aez_amd64_aesni_asm/aez_amd64.S", "-c", "-o"])
                       .arg(&format!("{}/aez_amd64.o", out_dir))
                       .status().unwrap();
    Command::new("ar").args(&["crs", "libaez.a", "aez_amd64.o"])
                      .current_dir(&Path::new(&out_dir))
                      .status().unwrap();
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=aez");
}
