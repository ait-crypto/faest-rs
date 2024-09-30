# Pure Rust implementation of the FAEST digital signature scheme

[FAEST](https://faest.info/) is a digital signature algorithm designed to be
secure against quantum computers. The security of FAEST is based on standard
cryptographic hashes and ciphers, specifically SHA3 and AES, which are
believed to remain secure against quantum adversaries.

This crate provides an implementation of FAEST written in Rust.