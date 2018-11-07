
# AEZ
[![](https://travis-ci.org/david415/aez.png?branch=master)](https://www.travis-ci.org/david415/aez) [![](https://img.shields.io/crates/v/aez.svg)](https://crates.io/crates/aez) [![](https://docs.rs/aez/badge.svg)](https://docs.rs/aez/)

The AEZ wide-block cipher: [AEZ](http://web.cs.ucdavis.edu/~rogaway/aez/)

This is a rust crate that wraps Ted Krovetz's AEZv5 implementation
in C using AES-NI hardware optimizations.

# status

Tests using test vectors pass.

# warning

This code has not been formally audited. Use it at your own risk!


# usage

To import `aez`, add the following to the dependencies section of
your project's `Cargo.toml`:
```toml
aez = "^0.0.3"
```
Then import the crate as:
```rust,no_run
extern crate aez;
```

# acknowledgments

Thanks to Ted Krovetz who wrote the AEZ v5 cipher in C with AES-NI and vector
intrinsics hardware optimizations.


# license

The license file has been included in the root directory of this crate
and is entitled **LICENSE**, the GNU AFFERO GENERAL PUBLIC LICENSE.
