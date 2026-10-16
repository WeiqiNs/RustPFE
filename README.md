# Pairing-based Functional Encryption in Rust (RustPFE)

[![RustPFE CI](https://github.com/WeiqiNs/RustPFE/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/WeiqiNs/RustPFE/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/WeiqiNs/RustPFE/graph/badge.svg)](https://codecov.io/gh/WeiqiNs/RustPFE)

Functional encryption lets the holder of a key learn one function of encrypted data, such as an inner product, and
nothing else. RustPFE implements eight published pairing-based schemes in safe Rust, six function-hiding inner-product
functional encryption (IPFE) schemes and two quadratic functional encryption (QFE) schemes, generic over any
[arkworks](https://github.com/arkworks-rs/algebra) pairing curve, tested on BLS12-381 and BN254, with a PyO3 Python
binding.

```rust
use ark_bls12_381::Bls12_381;
use pfe::group::DlogTable;
use pfe::ipfe::opt;
use pfe::rand::rngs::OsRng;

let rng = &mut OsRng;
let msk = opt::setup::<Bls12_381, _>(3, rng)?;
let table = DlogTable::new(opt::base::<Bls12_381>(), -1000, 1000);
let sk = opt::keygen(&msk, &[1, 2, 3], rng)?;
let ct = opt::encrypt(&msk, &[4, -5, 6], rng)?;
assert_eq!(opt::decrypt(&table, &sk, &ct), Some(12));
```

```python
from pfe.ipfe import opt
import pfe

msk = opt.setup(3)
table = pfe.DlogTable(opt.base(), -1000, 1000)
assert opt.decrypt(table, opt.keygen(msk, [1, 2, 3]), opt.encrypt(msk, [4, -5, 6])) == 12
```

## What functional encryption is for

In ordinary encryption a key decrypts everything or nothing. In functional encryption the holder of the master key
issues keys for specific functions: a key for the vector y, applied to an encryption of x, yields ⟨x, y⟩ and nothing
else about x. That is enough for weighted sums, statistics or a linear classifier over data the computing party never
sees; quadratic FE extends it to degree-2 polynomials such as xᵀFy, and a function-hiding scheme also hides y, so
neither side learns the other's vector. The inner-product schemes here are secret-key (`encrypt` takes the master key),
the quadratic schemes public-key, and all rely on bilinear pairings, hence pairing-friendly curves such as BLS12-381.

## Highlights

- **Eight schemes from the literature**, tested together on BLS12-381 and BN254 through one generic test suite.
- **Fast and parallel.** A `parallel` feature, on by default, spreads the work over all cores with results identical
  to the sequential build. With Ojaswi et al.'s scheme on BLS12-381, a prepared key decrypts a length-10 inner product
  in about 1 ms, and 16 threads sharing one key reach about 4,300 decryptions per second.
- **Safe, thread-safe and hardened.** The crate is `#![forbid(unsafe_code)]`, every key and ciphertext is
  `Send + Sync`, a regression test pins a deadlock the parallel work once exposed, and decoding rejects truncated,
  trailing, out-of-range and off-curve input without allocating from untrusted lengths.
- **Python binding** with PyO3: the same API as `pfe.ipfe.opt` and friends, bytes and pickle support, and the GIL
  released so Python threads decrypt in parallel.
- **100% line coverage** in CI, clippy with warnings as errors, and tests with and without the `parallel` feature.

## Schemes

Inner-product FE, where a key for y decrypts a ciphertext of x to ⟨x, y⟩:

| Scheme | Module | Function hiding | Security | Paper |
| --- | --- | :---: | --- | --- |
| Bishop et al. | `pfe::ipfe::bjk` | weak | SXDH | [ASIACRYPT 2015](https://doi.org/10.1007/978-3-662-48797-6_20) |
| Tomida et al. | `pfe::ipfe::tao` | full | XDLIN | [ISC 2016](https://doi.org/10.1007/978-3-319-45871-7_24) |
| Kim et al. | `pfe::ipfe::kim` | full | generic group model | [SCN 2018](https://doi.org/10.1007/978-3-319-98113-0_29) |
| Lin | `pfe::ipfe::lin` | full | SXDH | [CRYPTO 2017](https://doi.org/10.1007/978-3-319-63688-7_20) |
| Kim, Kim and Seo | `pfe::ipfe::kks` | full | SXDH | [TCS 2019](https://doi.org/10.1016/j.tcs.2019.03.016) |
| Ojaswi et al. | `pfe::ipfe::opt` | full | generic group model | [CiC 2025](https://doi.org/10.62056/abe0zo-3y) |

Quadratic FE, where a key for a matrix F decrypts a ciphertext of (x, y) to xᵀFy and anyone with the public key can
encrypt:

| Scheme | Module | Security | Paper |
| --- | --- | --- | --- |
| Baltico et al. | `pfe::qfe::bcfg` | adaptive, generic group model | [CRYPTO 2017](https://doi.org/10.1007/978-3-319-63688-7_3) |
| Dufour-Sans et al. | `pfe::qfe::sgp` | generic group model | [NeurIPS 2019](https://proceedings.neurips.cc/paper_files/paper/2019/hash/9d28de8ff9bb6a3fa41fddfdc28f3bc1-Abstract.html) |

## Using it

Add `pfe = { git = "https://github.com/WeiqiNs/RustPFE" }` and a curve such as `ark-bls12-381 = "0.6"`.

- Every scheme has `setup`, `keygen`, `encrypt`, `prepare` and `decrypt`; randomized functions take the RNG, and
  `setup`, `keygen` and `encrypt` return `Err(ShapeError)` for a bad length or shape.
- `decrypt` returns `None` outside the searched range and accepts the key or the prepared key from `prepare(&sk)`,
  which precomputes its pairing work once. Bishop et al. and Kim et al. take the range directly; the others share one
  `DlogTable` built over `base()` (Tomida et al.: `msk.base()`).
- `MasterKey`, `PublicKey`, `Key` and `Ciphertext` implement `pfe::group::Encoding`: n as a 4-byte big-endian integer,
  then the fields in declaration order in arkworks' compressed form, with every length derived from n; `decode` returns
  a `pfe::group::DecodeError` for malformed input.
- `default-features = false` gives a sequential build; `RAYON_NUM_THREADS` bounds the parallel one.

The Python binding in `python/` (Python 3.11+) covers BLS12-381 with the same names, `pfe.ipfe.{bjk,tao,kim,lin,kks,opt}`,
`pfe.qfe.{bcfg,sgp}`, `pfe.DlogTable` and `pfe.DecodeError`; bad input raises `ValueError`, and values support
`bytes()`, `Type.from_bytes()` and pickle.

## Build and test

```bash
cargo test
cargo bench
cd python && pip install . && pytest tests
```

## The PFE family

LibPFE, GoPFE and RustPFE implement the same eight inner-product and quadratic functional encryption
schemes with the same test cases and benchmark inputs, so the three languages compare like for like; LibRBP is the
pairing layer under LibPFE.

| Repository | Language | Pairing backend | Role |
| --- | --- | --- | --- |
| [LibRBP](https://github.com/WeiqiNs/LibRBP) | C++20 | [RELIC](https://github.com/relic-toolkit/relic) | Typed, thread-safe pairing library: curves, groups, pairings, linear algebra, dlog tables |
| [LibPFE](https://github.com/WeiqiNs/LibPFE) | C++20 | LibRBP | The eight schemes as header-only templates over any LibRBP curve |
| [GoPFE](https://github.com/WeiqiNs/GoPFE) | Go | [gnark-crypto](https://github.com/Consensys/gnark-crypto) | The eight schemes on BLS12-381, parallel across `GOMAXPROCS` |
| **RustPFE** (this repo) | Rust, Python | [arkworks](https://github.com/arkworks-rs/algebra) | The eight schemes in safe Rust over any arkworks pairing curve, with a PyO3 Python binding |

Licensed under Apache-2.0.
