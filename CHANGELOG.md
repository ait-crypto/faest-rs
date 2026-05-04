# Changelog

## 0.3 (2026-05-04)

* Upgrade to `signature` version 0.3.
* Upgrade to `rand` and `rand_core` version 0.10.
* Upgrade to `sha3`, `aes`, and `ctr`.
* Remove use of `generic_array`.
* Improve timing side-channel resistance.
* Bump MSRV to 1.88.

## 0.2.2 (2025-12-17)

* Improve dynamic dispatch of AVX2 optimized codepaths.
* Add initial support for `no_std` builds. (#15)

## 0.2.1 (2025-05-16)

* Add unpacked secret keys with pre-computed witnesses.
  For repeated signing with the same secret key, unpacked secret keys provide a
  runtime/memory trade-off.
* Internal refactoring.

## 0.2 (2025-05-03)

* Implement version 2 of the FAEST specification.
* Bump edition to 2024.

## 0.1.3 (2025-01-09)

* Update itertools to 0.14.
* Fix clippy warnings.

## 0.1.2 (2024-12-14)

* Fix debug assertions.

## 0.1.1 (2024-12-14)

* AVX2-based optimizations of 192 bit field arithmetic.

## 0.1 (2024-12-11)

* AVX2-based optimizations of 128 and 256 bit field arithmetic.

## 0.0.2 (2024-10-17)

* Small improvements and refactoring of code base.

## 0.0.1 (2024-10-16)

* Initial release.
