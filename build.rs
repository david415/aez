// build.rs

use std::env;
use std::path::Path;


fn main() {
    let project_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_path = Path::new(&project_dir);
    let lib_path_str = project_path.join("artifacts");
    println!("cargo:rustc-link-search={}", lib_path_str.to_str().unwrap()); // the "-L" flag
    println!("cargo:rustc-link-lib=aez"); // the "-l" flag
}

