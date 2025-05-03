# Pure Rust implementation of the FAEST digital signature scheme

[FAEST](https://faest.info/) is a digital signature algorithm designed to be secure against quantum
computers. The security of FAEST is based on standard cryptographic hashes and ciphers, specifically
SHA3 and AES, which are believed to remain secure against quantum adversaries.

This crate provides an implementation of FAEST written in Rust. The implementation is compatible
with version 2 of the FAEST specification.

## Security Notes

This crate has received no security audit. Use at your own risk.

## License

This crate is licensed under Apache-2.0 or the MIT license. Some parts of `src/rijndael_32.rs` are
based on the bitspliced implementation of AES from the [aes](https://crates.io/crates/aes) crate
which is licensed under [Apache License version 2.0](http://www.apache.org/licenses/LICENSE-2.0) or
the MIT license.

## Acknowledgments

This work has received funding from the Austrian security research programme of the Federal Ministry
of Finance (BMF) as part of the project [PREPARED](https://prepared-eid.at/) and from the
DIGITAL-2021-QCI-01 Digital European Program under Project number No 101091642
([QCI-CAT](https://qci-cat.at/)) and the National Foundation for Research, Technology and
Development.
