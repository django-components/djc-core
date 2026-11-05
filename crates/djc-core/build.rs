// Sets `cfg(PyPy)` and the other interpreter flags that `src/lib.rs` depends on.
fn main() {
    pyo3_build_config::use_pyo3_cfgs();
}
