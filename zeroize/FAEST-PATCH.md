# Private benchmark patch

Based on crates.io zeroize 1.9.1, with upstream source, tests and MIT/Apache
licenses retained. Not for publication.

The optional explicit-bzero feature changes only zeroize_flat_type: it wipes
size_of::<F>() bytes using libc::explicit_bzero, skipping zero-sized types.
Other zeroization paths remain upstream implementations. The feature requires
Linux GNU and glibc >= 2.25 with no fallback; libc defaults are disabled.
Without the feature the crate retains upstream behavior and no_std support.
