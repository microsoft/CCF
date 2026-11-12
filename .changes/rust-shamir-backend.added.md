The experimental `USE_RUST_SHAMIR` build option selects a Rust implementation of recovery share secret sharing, whose extracted Lean model is proved to refine CSLib's Shamir scheme.
The default remains the C++ implementation, and both read and write the same recovery shares; see [build switches](doc/contribute/build_ccf.rst#build-switches).
