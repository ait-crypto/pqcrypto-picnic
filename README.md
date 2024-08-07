# Picnic implementation for `pqcrypto`

This crate provides bindings for the [optimized implementation](https://github.com/IAIK/Picnic) of the [Picnic](https://microsoft.github.io/Picnic/) digital signature scheme. It implements the traits of the [pqcrypto-traits](https://crates.io/crates/pqcrypto-traits) crate.

## Features

This crate supports the following features:
* `picnic` (default): Enable the Picnic parameter sets with ZKB++/Fiat-Shamir as proof system.
* `unruh-transform`: Enable the Picnic parameter sets with ZKB++/Unruh as proof system.
* `picnic3` (default): Enable the Picnic parameter sets with KKW/Fiat-Shamir as proof system.
* `system` (default): Use the shared library of Picnic per default.
* `static-fallback` (default): Build Picnic on demand if shared library is not available.
* `std` (default): Use `std`.
* `serialization`: Enable serialization with [serde](https://serde.rs).
* `zeroize`: Enable zeroization of secret keys with the `zeroize` crate.

If the crate is not built with `std` enabled, the `alloc` crates is used.

## Security Notes

This crate has received no security audit. Use at your own risk.

## License

This crate is licensed under the MIT license.
