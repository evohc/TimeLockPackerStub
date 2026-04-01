fn main() {
    println!("cargo:rustc-link-arg=/ENTRY:mainCRTStartup");
    println!("cargo:rustc-link-arg=/SUBSYSTEM:CONSOLE");
    println!("cargo:rustc-link-arg=/NODEFAULTLIB"); // no C runtime.
}