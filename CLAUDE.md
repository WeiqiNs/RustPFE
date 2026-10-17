# RustPFE

Pairing-based functional encryption in safe Rust: function-hiding inner-product (IPFE) and quadratic (QFE) schemes,
generic over `ark_ec::pairing::Pairing`, tested on BLS12-381 and BN254. `python/` is a PyO3 binding on BLS12-381,
imported as `pfe`; PrivateRetrieval depends on it through a commit-pinned git URL in its `pyproject.toml`. LibPFE (C++),
GoPFE (Go) and CudaPFE (CUDA) implement the same schemes, and LibPFE, GoPFE and RustPFE share test cases and benchmark
inputs. `README.md` is the user-facing overview with the scheme table.

## Commands

As `.github/workflows/ci.yml` runs them, from the root (`cargo test` locally is the default-feature run that CI does
inside `llvm-cov`):

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo test --no-default-features
cargo llvm-cov --tests --ignore-filename-regex '(tests|benches)/' --lcov --output-path lcov.info
cargo llvm-cov report --ignore-filename-regex '(tests|benches)/' --fail-under-lines 100 --summary-only
cargo bench --bench schemes -- --test
```

From `python/`, in an activated venv on a Python that `requires-python` in `python/pyproject.toml` allows (CI pins the
mypy version; `maturin develop --release` rebuilds faster while iterating):

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings
python stubgen.py && test -z "$(git status --porcelain .)"
python -m pip install pytest mypy && python -m pip install .
python -m pytest tests -q && python -m mypy.stubtest pfe
```

## Layout

- `src/group.rs`: curve aliases (`Scalar`, `G1`, `G2`, `Gt`, `G2Prepared`), cached fixed-base multiplication
  (`g1_mul_vec`, `g2_mul_vec`, `masked_g1`, `masked_g2`), `pair`, `PairingProduct`, and `Dimension` with its
  `dimension!` macro. Its submodules: `linalg.rs` (`Matrix`, `VectorOps`, `ShapeError`, `check_dimension`,
  `int_vector`/`int_matrix` for `i64` input), `dlog.rs` (`DlogTable`, baby-step giant-step, and one-shot `dlog`),
  `encoding.rs` (`Encoding`, `Encoder`, `Decoder`, `decode`, `DecodeError`).
- `src/ipfe/`, `src/qfe/`: one module per scheme, listed in `src/ipfe.rs` and `src/qfe.rs`.
- `tests/common/mod.rs`: the `InnerProductScheme`/`QuadraticScheme` adapters that `tests/schemes.rs` (generic cases per
  scheme and curve) and `benches/schemes.rs` (criterion) run through. `tests/group.rs` covers the group layer.
- `python/src/`: `scheme.rs` (the `ipfe_module!`/`qfe_module!` macros), `ipfe.rs`/`qfe.rs` (their invocations),
  `table.rs` (`Gt`, `DlogTable`), `errors.rs` (error mapping). `python/tests/` is the pytest suite.
- `.cargo/config.toml` enables `bmi2` and `adx` on x86_64 for ark-ff's `asm` feature, for cargo runs inside this
  repo only.

## Schemes and data flow

Each scheme module has `setup`, `keygen`, `encrypt`, `prepare`, `decrypt` over `MasterKey`, `Key`, `Ciphertext` and
`PreparedKey`. IPFE `encrypt` takes the master key; QFE `setup` also returns a `PublicKey` that `encrypt` takes.
`prepare` converts a key's G2 points to `G2Prepared`, and a per-module `DecryptionKey` trait lets `decrypt` accept
either form. `decrypt` computes a target-group element with `pair` or `PairingProduct` and returns its discrete log, or
`None` outside the range. Most schemes share one `DlogTable` over `base()` (`tao`: `MasterKey::base`); `bjk` and `kim`
take `lo, hi` and call `dlog`, because their base depends on the key and ciphertext.

A new scheme changes together: the module and its `pub mod`; an adapter in `tests/common/mod.rs` and rows in the
`inner_product_tests!`/`quadratic_tests!` invocations in `tests/schemes.rs`; `every_scheme` in `benches/schemes.rs`; an
`ipfe_module!`/`qfe_module!` call and `register` in `python/src/`; `SCHEMES` in `python/stubgen.py` plus the regenerated
stubs; the lists in `python/tests/conftest.py`; the README tables; the sibling repos.

## Design facts

- `parallel` (default) runs `group::prepare`, `masked`, `VectorOps::mul_mat` and `Matrix::invert` on rayon with results
  identical to the sequential build; CI tests both. `combine` in `src/group.rs` stays sequential because rayon worker
  stacks overflowed inside arkworks' MSM.
- `generator_table` builds outside the `GENERATOR_TABLES` mutex and inserts with `or_insert_with`, because holding the
  lock across the rayon-parallel build deadlocked; `tests/tables.rs` pins it. One table is leaked per group `TypeId`
  (`cached_generator_tables_are_per_curve` in `tests/group.rs`).
- `#![forbid(unsafe_code)]`. Keys, ciphertexts and decryptors are `Send + Sync`, asserted by the adapter traits' bounds
  and exercised by `decrypt_concurrently` in `tests/schemes.rs`.
- Scheme fields are private. `setup` rejects n outside `check_dimension` and `keygen`/`encrypt` reject wrong shapes, as
  `Err(ShapeError)`; `decrypt` panics on a key and ciphertext of different n (`panics_on_mismatched_*` in
  `tests/schemes.rs`).
- Encodings are n as 4 big-endian bytes, then the fields in declaration order in ark-serialize compressed form, every
  length derived from n. They go through `Encoder`/`decode` instead of arkworks' derives, whose length prefixes could
  disagree with n and which cannot reject trailing bytes; element sizes come from `compressed_size()`. `decode` bounds n
  by the input length before allocating and rejects truncated, trailing, out-of-range and off-curve input
  (`decode_accepts_well_formed_input_and_rejects_malformed_input` in `tests/group.rs`). PrivateRetrieval stores `opt`
  encodings under `PFE_VERSION` in `src/privret/fileformat.py`, so changing that format means bumping it there.

## Python binding

maturin builds the extension as `pfe.pfe` in the mixed layout (`[tool.maturin]` in `python/pyproject.toml`):
`python/python/pfe` holds only the re-export shim `__init__.py`, `py.typed` and stubs, `pfe.pyi` mirroring the shim.
`pfe.ipfe.*` and `pfe.qfe.*` exist only at runtime (`add_submodule` in `python/src/scheme.rs` registers them in
`sys.modules`), so their directories hold only `.pyi`. `stubgen.py` renders those stubs from one template and its
`SCHEMES` table, which mirrors the macro invocations; the root `__init__.pyi` is hand-written. CI fails if regenerated
stubs differ from the committed ones or if stubtest disagrees with the built extension.

The binding validates before calling Rust, so Python gets exceptions rather than panics: `errors::check_match` compares
key and ciphertext n, and `table::check_bounds` orders the range and caps its span at `MAX_SPAN`. `ShapeError` becomes
`ValueError`, `DecodeError` becomes `pfe.DecodeError` (a `ValueError`). Work runs inside `py.detach`, releasing the GIL.
Encoded types support `bytes()`, `from_bytes` and pickle; `PreparedKey` and `DlogTable` do not.

## CI

`.github/workflows/ci.yml` runs on pushes and PRs to main: `coverage` (format, both clippy runs, sequential tests,
coverage with the 100% line gate, Codecov upload over OIDC), `bench` (each benchmark once), and `python` (the binding
commands across the job's Python matrix). The `python/` crate is outside the coverage gate.
