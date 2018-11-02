// build.rs

use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    Command::new("gcc").args(&["-g", "-O0", "-Wall", "-msse2", "-march=native", "-maes", "-fPIC", "-c",
                               "aez_amd64_aesni_c/encrypt.c", "aez_ref_c/slow_encrypt.c",
                               "aez_ref_c/rijndael-alg-fst.c", "aez_ref_c/blake2b.c"])
        .current_dir(&Path::new(&out_dir))
        .status().unwrap();
    Command::new("ar").args(&["crs", "libaez.a", "slow_encrypt.o", "encrypt.o", "rijndael-alg-fst.o", "blake2b.o"])
        .current_dir(&Path::new(&out_dir))
        .status().unwrap();
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=aez");
}
