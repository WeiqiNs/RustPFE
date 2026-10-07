# Pairing-based Functional Encryption in Rust (RustPFE)

[![RustPFE CI](https://github.com/WeiqiNs/RustPFE/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/WeiqiNs/RustPFE/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/WeiqiNs/RustPFE/graph/badge.svg)](https://codecov.io/gh/WeiqiNs/RustPFE)

**RustPFE** is a Rust library of pairing-based functional encryption: private-key *function-hiding* inner-product
functional encryption (IPFE) and public-key quadratic functional encryption (QFE). Every scheme is generic over an
[arkworks](https://github.com/arkworks-rs/algebra) pairing curve and is tested on BLS12-381 and BN254. It is the Rust
counterpart of [LibPFE](https://github.com/WeiqiNs/LibPFE) and [GoPFE](https://github.com/WeiqiNs/GoPFE), with the
same constructions and the same tests.

## Supported schemes

### Inner-product FE

A key for y decrypts a ciphertext of x to the inner product ⟨x, y⟩.

| Scheme | Module | Function hiding | Security | Ciphertext | Fixed-base `decrypt` | Reference |
| --- | --- | :---: | --- | :---: | :---: | --- |
| Bishop et al. | `pfe::ipfe::bjk` | weak | SXDH | 2n + 6 | no | [ASIACRYPT 2015](https://doi.org/10.1007/978-3-662-48797-6_20) |
| Tomida et al. | `pfe::ipfe::tao` | full | XDLIN | 2n + 5 | yes | [ISC 2016](https://doi.org/10.1007/978-3-319-45871-7_24) |
| Kim et al. | `pfe::ipfe::kim` | full | SIM, generic group model | n + 1 | no | [SCN 2018](https://doi.org/10.1007/978-3-319-98113-0_29) |
| Lin | `pfe::ipfe::lin` | full | SXDH | 2n + 2 | yes | [CRYPTO 2017](https://doi.org/10.1007/978-3-319-63688-7_20) |
| Kim, Kim and Seo | `pfe::ipfe::kks` | full | SXDH | 2n + 8 | yes | [TCS 2019](https://doi.org/10.1016/j.tcs.2019.03.016) |
| Ojaswi et al. | `pfe::ipfe::opt` | full | SIM, generic group model | n + 4 | yes | [CiC 2025](https://doi.org/10.62056/abe0zo-3y) |

For vectors of length n, a ciphertext has the listed number of G1 elements and a key the same number of G2 elements.
Lin's scheme is the paper's weakly function-hiding scheme, lifted to full function hiding as the paper describes.

### Quadratic FE

A key for an n × n matrix F decrypts a ciphertext of (x, y) to xᵀFy. Anyone with the public key can encrypt.

| Scheme | Module | Security | Ciphertext | Key | Reference |
| --- | --- | --- | :---: | :---: | --- |
| Baltico et al. | `pfe::qfe::bcfg` | adaptive, generic group model | 2n G1 + (2n + 2) G2 | (n + 2) G1 + n G2 | [CRYPTO 2017](https://doi.org/10.1007/978-3-319-63688-7_3) |
| Dufour-Sans et al. | `pfe::qfe::sgp` | generic group model | (2n + 1) G1 + 2n G2 | 1 G2 | [NeurIPS 2019](https://proceedings.neurips.cc/paper_files/paper/2019/hash/9d28de8ff9bb6a3fa41fddfdc28f3bc1-Abstract.html) |

Both decrypt against a fixed base, and keys also carry F. A Baltico et al. key also carries the products of F with the
master key that decryption would otherwise derive from the public key. Dufour-Sans et al.'s scheme appears in the
NeurIPS paper by Ryffel, Dufour-Sans, Gay, Bach and Pointcheval.

## Usage

```toml
[dependencies]
pfe = { git = "https://github.com/WeiqiNs/RustPFE" }
ark-bls12-381 = "0.6"
```

```rust
use ark_bls12_381::Bls12_381;
use pfe::group::DlogTable;
use pfe::ipfe::opt;
use pfe::qfe::sgp;
use pfe::rand::rngs::OsRng;

let rng = &mut OsRng;
let msk = opt::setup::<Bls12_381, _>(3, rng);
let table = DlogTable::new(opt::base::<Bls12_381>(), -1000, 1000);
let sk = opt::keygen(&msk, &[1, 2, 3], rng)?;
let ct = opt::encrypt(&msk, &[4, -5, 6], rng)?;
let result = opt::decrypt(&table, &sk, &ct);

let (pk, msk) = sgp::setup::<Bls12_381, _>(2, rng);
let table = DlogTable::new(sgp::base::<Bls12_381>(), -1000, 1000);
let sk = sgp::keygen(&msk, &[[1, 2], [0, -1]])?;
let ct = sgp::encrypt(&pk, &[3, 4], &[5, -6], rng)?;
let result = sgp::decrypt(&table, &sk, &ct);
```

`keygen` and `encrypt` return `Err(ShapeError)` when an input has the wrong length or shape, and `decrypt` returns
`None` when the result falls outside the searched range. Schemes with a fixed-base `decrypt` take a `DlogTable` built
once for a range (over `msk.base` for Tomida et al. and `base()` for the others) and reused across decryptions; Bishop
et al. and Kim et al. derive the base from each key and ciphertext, so their `decrypt` takes the bounds instead. Every
randomized function takes the random number generator explicitly.

`decrypt_many` takes the same arguments as `decrypt` but a slice of ciphertexts, and returns one result per
ciphertext. It prepares the key's G2 elements for pairing once and reuses them, so decrypting many ciphertexts under
one key costs less per ciphertext than calling `decrypt` for each.

The `group` module wraps arkworks with the operations the schemes need: vectors and matrices over the scalar field,
fixed-base and multi-scalar multiplication, multi-pairing products and baby-step giant-step discrete logarithms.
Fixed-base multiplication reuses one table of generator multiples per curve group, built on first use and kept for the
life of the process.

## Benchmarks

`benches/schemes.rs` times every scheme on BLS12-381 and BN254 with the same input sizes and bounds as LibPFE's and
GoPFE's benchmarks, and checks each decryption against the true result before timing it. Run it with `cargo bench`.

The numbers below are milliseconds per operation on BLS12-381, measured with Rust 1.99 and arkworks 0.6 on an AMD Ryzen
7 9800X3D. Inputs are random vectors (and matrices) whose results lie in [0, 10000]. Fixed-base schemes reuse one
discrete-log table, which is excluded from Dec; Bishop et al. and Kim et al. search the range on every decryption. "Dec,
reused key" is `decrypt_many` over 10 ciphertexts, divided by 10.

Inner-product FE, n = 10:

| Scheme | Setup | KeyGen | Enc | Dec | Dec, reused key |
| --- | ---: | ---: | ---: | ---: | ---: |
| Bishop et al. | 0.41 | 0.87 | 0.31 | 6.64 | 5.03 |
| Tomida et al. | 1.50 | 0.82 | 0.28 | 5.48 | 3.95 |
| Kim et al. | 0.06 | 0.38 | 0.14 | 3.82 | 3.06 |
| Lin | 0.00 | 0.72 | 0.25 | 5.07 | 3.63 |
| Kim, Kim and Seo | 0.00 | 0.91 | 0.31 | 6.02 | 4.28 |
| Ojaswi et al. | 0.02 | 0.47 | 0.17 | 3.28 | 2.45 |

Inner-product FE, n = 100:

| Scheme | Setup | KeyGen | Enc | Dec | Dec, reused key |
| --- | ---: | ---: | ---: | ---: | ---: |
| Bishop et al. | 188.74 | 7.27 | 2.87 | 43.23 | 30.78 |
| Tomida et al. | 194.93 | 7.16 | 2.75 | 42.07 | 29.78 |
| Kim et al. | 22.78 | 3.43 | 1.26 | 21.76 | 15.60 |
| Lin | 0.01 | 6.49 | 2.42 | 41.50 | 29.51 |
| Kim, Kim and Seo | 0.02 | 6.68 | 2.27 | 43.94 | 31.11 |
| Ojaswi et al. | 0.02 | 3.36 | 1.15 | 21.62 | 14.86 |

Quadratic FE, n = 10:

| Scheme | Setup | KeyGen | Enc | Dec | Dec, reused key |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baltico et al. | 0.48 | 0.43 | 8.22 | 6.99 | 6.36 |
| Dufour-Sans et al. | 0.45 | 0.04 | 8.19 | 5.10 | 5.04 |

Quadratic FE, n = 100:

| Scheme | Setup | KeyGen | Enc | Dec | Dec, reused key |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baltico et al. | 4.35 | 4.81 | 76.53 | 65.55 | 57.87 |
| Dufour-Sans et al. | 4.32 | 0.34 | 78.22 | 46.37 | 45.96 |

## Testing

```bash
cargo test
cargo llvm-cov --tests --ignore-filename-regex '(tests|benches)/' --fail-under-lines 100
```

`tests/schemes.rs` runs the same cases against every scheme on both curves, and CI requires 100% line coverage.
