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
| Baltico et al. | `pfe::qfe::bcfg` | adaptive, generic group model | 2n G1 + (2n + 2) G2 | 2 G1 | [CRYPTO 2017](https://doi.org/10.1007/978-3-319-63688-7_3) |
| Dufour-Sans et al. | `pfe::qfe::sgp` | generic group model | (2n + 1) G1 + 2n G2 | 1 G2 | [NeurIPS 2019](https://proceedings.neurips.cc/paper_files/paper/2019/hash/9d28de8ff9bb6a3fa41fddfdc28f3bc1-Abstract.html) |

Both decrypt against a fixed base, and keys also carry F. Dufour-Sans et al.'s scheme appears in the NeurIPS paper by
Ryffel, Dufour-Sans, Gay, Bach and Pointcheval.

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
et al. and Kim et al. derive the base from each key and ciphertext, so their `decrypt` takes the bounds instead. Baltico
et al.'s `decrypt` also takes the public key. Every randomized function takes the random number generator explicitly.

The `group` module wraps arkworks with the operations the schemes need: vectors and matrices over the scalar field,
fixed-base and multi-scalar multiplication, multi-pairing products and baby-step giant-step discrete logarithms.

## Benchmarks

`benches/schemes.rs` times every scheme on BLS12-381 and BN254 with the same input sizes and bounds as LibPFE's and
GoPFE's benchmarks, and checks each decryption against the true result before timing it. Run it with `cargo bench`.

The numbers below are milliseconds per operation on BLS12-381, measured with Rust 1.99 and arkworks 0.6 (with its
x86-64 assembly field arithmetic) on an AMD Ryzen 7 9800X3D. Inputs are random vectors (and matrices) whose results lie
in [0, 10000]. Fixed-base schemes reuse one discrete-log table, which is excluded from Dec; Bishop et al. and Kim et al.
search the range on every decryption.

Inner-product FE, n = 10:

| Scheme | Setup | KeyGen | Enc | Dec |
| --- | ---: | ---: | ---: | ---: |
| Bishop et al. | 0.59 | 6.18 | 2.76 | 6.92 |
| Tomida et al. | 1.71 | 4.01 | 1.60 | 5.68 |
| Kim et al. | 0.07 | 3.02 | 1.32 | 3.82 |
| Lin | 0.00 | 3.78 | 1.59 | 5.25 |
| Kim, Kim and Seo | 0.00 | 4.09 | 1.66 | 6.09 |
| Ojaswi et al. | 0.02 | 4.92 | 2.30 | 3.27 |

Inner-product FE, n = 100:

| Scheme | Setup | KeyGen | Enc | Dec |
| --- | ---: | ---: | ---: | ---: |
| Bishop et al. | 304.97 | 16.98 | 6.40 | 43.57 |
| Tomida et al. | 301.15 | 14.36 | 5.25 | 42.65 |
| Kim et al. | 37.16 | 9.52 | 3.26 | 22.03 |
| Lin | 0.01 | 14.71 | 4.85 | 42.35 |
| Kim, Kim and Seo | 0.01 | 13.89 | 4.73 | 43.00 |
| Ojaswi et al. | 0.02 | 10.76 | 4.14 | 21.42 |

Quadratic FE, n = 10:

| Scheme | Setup | KeyGen | Enc | Dec |
| --- | ---: | ---: | ---: | ---: |
| Baltico et al. | 4.57 | 0.15 | 15.33 | 7.32 |
| Dufour-Sans et al. | 3.95 | 0.29 | 15.10 | 5.00 |

Quadratic FE, n = 100:

| Scheme | Setup | KeyGen | Enc | Dec |
| --- | ---: | ---: | ---: | ---: |
| Baltico et al. | 12.12 | 0.46 | 85.33 | 69.67 |
| Dufour-Sans et al. | 11.54 | 0.61 | 88.81 | 45.89 |

## Testing

```bash
cargo test
cargo llvm-cov --tests --ignore-filename-regex '(tests|benches)/' --fail-under-lines 100
```

`tests/schemes.rs` runs the same cases against every scheme on both curves, and CI requires 100% line coverage.
