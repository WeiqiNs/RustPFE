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
let prepared = opt::prepare(&sk);
let same_result = opt::decrypt(&table, &prepared, &ct);

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

Every scheme also has `prepare(&sk)`, which precomputes the key's pairing lines once (arkworks' `G2Prepared`) and
returns a `PreparedKey`. `decrypt` accepts either a `Key` or a `PreparedKey`, the two types implementing the scheme's
`DecryptionKey` trait, and returns the same result for both. An IPFE key is all of its decryption's G2 side, so its
prepared `decrypt` costs about two thirds to three quarters of `decrypt` with the key; prepare a key that will decrypt
many ciphertexts. A QFE decryption also pairs the ciphertext's own G2 points, which no key can prepare, so a prepared
Baltico et al. key saves less, and a prepared Dufour-Sans et al. key, which fixes one G2 point, decrypts in about the
time of the plain key. A prepared key holds about 20 KB per G2 point on BLS12-381.

The `group` module wraps arkworks with the operations the schemes need: vectors and matrices over the scalar field,
fixed-base and multi-scalar multiplication, multi-pairing products and baby-step giant-step discrete logarithms.
Fixed-base multiplication reuses one table of generator multiples per curve group, built on first use and kept for the
life of the process.

## Benchmarks

`benches/schemes.rs` times every scheme on BLS12-381 and BN254 with the same input sizes and bounds as LibPFE's and
GoPFE's benchmarks, and checks each decryption against the true result before timing it. Run it with `cargo bench`.

The numbers below are milliseconds per operation on BLS12-381 on one core (`taskset -c 2`), measured with Rust 1.99 and
arkworks 0.6 on an AMD Ryzen 7 9800X3D. Inputs are random vectors (and matrices) whose results lie in [0, 10000].
Fixed-base schemes reuse one discrete-log table, which is excluded from Dec; Bishop et al. and Kim et al. search the
range on every decryption. Prepare is the one-time cost of `prepare(&sk)`, and Prepared Dec decrypts with the prepared
key.

Inner-product FE, n = 10:

| Scheme | Setup | KeyGen | Enc | Dec | Prepare | Prepared Dec |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Bishop et al. | 0.43 | 0.88 | 0.32 | 6.82 | 1.84 | 4.95 |
| Tomida et al. | 1.56 | 0.84 | 0.30 | 5.68 | 1.76 | 3.87 |
| Kim et al. | 0.07 | 0.40 | 0.15 | 3.91 | 0.73 | 3.10 |
| Lin | 0.00 | 0.73 | 0.26 | 5.11 | 1.66 | 3.66 |
| Kim, Kim and Seo | 0.00 | 0.95 | 0.32 | 6.28 | 1.97 | 4.33 |
| Ojaswi et al. | 0.02 | 0.49 | 0.18 | 3.43 | 0.95 | 2.36 |

Inner-product FE, n = 100:

| Scheme | Setup | KeyGen | Enc | Dec | Prepare | Prepared Dec |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Bishop et al. | 197.57 | 7.57 | 3.01 | 44.49 | 15.45 | 29.79 |
| Tomida et al. | 202.62 | 7.73 | 2.89 | 43.57 | 15.44 | 28.35 |
| Kim et al. | 23.75 | 3.59 | 1.33 | 23.53 | 7.32 | 15.10 |
| Lin | 0.01 | 6.64 | 2.27 | 42.59 | 15.57 | 29.07 |
| Kim, Kim and Seo | 0.02 | 7.08 | 2.42 | 45.28 | 16.26 | 30.02 |
| Ojaswi et al. | 0.02 | 3.47 | 1.31 | 23.75 | 7.70 | 15.10 |

Quadratic FE, n = 10:

| Scheme | Setup | KeyGen | Enc | Dec | Prepare | Prepared Dec |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baltico et al. | 0.59 | 0.59 | 8.59 | 7.31 | 0.65 | 6.62 |
| Dufour-Sans et al. | 0.48 | 0.04 | 8.86 | 5.41 | 0.07 | 5.34 |

Quadratic FE, n = 100:

| Scheme | Setup | KeyGen | Enc | Dec | Prepare | Prepared Dec |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baltico et al. | 4.62 | 5.03 | 80.16 | 67.29 | 7.32 | 61.24 |
| Dufour-Sans et al. | 4.64 | 0.37 | 84.42 | 48.13 | 0.07 | 48.89 |

## Testing

```bash
cargo test
cargo llvm-cov --tests --ignore-filename-regex '(tests|benches)/' --fail-under-lines 100
```

`tests/schemes.rs` runs the same cases against every scheme on both curves, and CI requires 100% line coverage.
