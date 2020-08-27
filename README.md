## THIS IS PROTOTYPE CODE FOR RESEARCH - NOT SUITABLE OR TESTED FOR PRODUCTION USAGE

This software is for performance testing ONLY! It may have security
vulnerabilities that could be exploited in any read-world deployment.

# Bellare-Shoup aggregatable one-time signatures

This repo contains a prototype implementation of the Bellare-Shoup aggregatable
one-time signatures. These are cryptographic digital signatures that have
aggregatable properties: one can aggregate multiple signatures into a single
short digital signature.

For the accompanying research paper, see: https://crypto.stanford.edu/~skim13/agg_ots.pdf.

## Installation & Usage

Requires Rust - https://rustup.rs/

Once installed, you can download with:

```bash
git clone https://github.com/samkim-crypto/bs_agg_ots/
cd recrypt
cargo build
# Optional: builds and opens documentation
cargo doc --no-deps --open
```

By default, running with `cargo run` gives the benchmarks. Ensure to run with
`cargo run --release` to get profiles for optimised code.
