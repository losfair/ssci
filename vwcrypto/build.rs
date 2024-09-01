fn main() {
    println!("cargo:rustc-env=EMCC_CFLAGS=--no-entry");
}