fn main() {
    println!("cargo:rustc-link-arg=--export=__stack_pointer");
}
