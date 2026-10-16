# RustPFE for agents

Rust functional encryption over arkworks: six inner-product (IPFE) and two quadratic (QFE) schemes, generic over
`ark_ec::pairing::Pairing` and tested on BLS12-381 and BN254, the Rust counterpart of LibPFE and GoPFE. `python/` binds
it for Python. `README.md` is the user-facing overview.

## Commands

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo test
cargo test --no-default-features
cargo llvm-cov --tests --ignore-filename-regex '(tests|benches)/' --fail-under-lines 100 --summary-only
cargo bench --bench schemes -- --test
```

CI runs the same checks; its default-feature test run happens inside the coverage step.

## Python binding

`python/` is a standalone PyO3 crate on BLS12-381; the root commands never build it and it is outside the coverage
gate. From `python/`, inside an activated Python 3.11+ virtual environment:

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings
python stubgen.py && test -z "$(git status --porcelain .)"   # the committed stubs match their template
python -m pip install . && python -m pytest tests -q   # as CI; maturin develop --release to iterate
python -m pip install mypy && python -m mypy.stubtest pfe   # the stubs match the installed binding
```

The binding checks key and ciphertext lengths and dlog bounds before calling Rust, so Python never sees a panic.

maturin builds the extension as `pfe.pfe` in the mixed layout: `python/python/pfe` holds only the re-export shim
`__init__.py`, `py.typed` and the type stubs, including `pfe.pyi`, which mirrors the shim for the extension module. The
`pfe.ipfe` and `pfe.qfe` scheme modules exist only at runtime, created by the extension and registered in `sys.modules`,
so their directories hold stubs and no `.py`. `stubgen.py` renders the family and scheme stubs from one template and a
table mirroring the `ipfe_module!` and `qfe_module!` calls; the root `__init__.pyi` is hand-written. Any change to a
scheme's Python surface updates `stubgen.py` and regenerates the stubs, or stubtest fails.

## Invariants

- Results are identical with and without the `parallel` feature. `combine` in `src/group.rs` stays sequential: on rayon
  it overflowed worker stacks inside arkworks' MSM.
- Never hold a `std` lock across work that may run on rayon's pool; `generator_table` builds outside its mutex, and
  `tests/tables.rs` pins the deadlock this avoids.
- `#![forbid(unsafe_code)]`. Every key, ciphertext and `DlogTable` is `Send + Sync` and immutable; the adapter traits in
  `tests/common/mod.rs` assert the bounds.
- Scheme struct fields are private. `setup`, `keygen` and `encrypt` return `Err(ShapeError)` for bad shapes, and a key
  and ciphertext of different n panic in `decrypt` (pinned in `tests/schemes.rs`).
- Encodings are a 4-byte big-endian n, then the fields in declaration order in ark-serialize compressed form, with
  every length derived from n. Arkworks' derive macros are not used: their length prefixes could disagree with n, and
  they cannot reject trailing bytes. Element sizes come from `compressed_size()`, never literals.
- LibPFE, GoPFE and RustPFE keep the same constructions, test cases and benchmark inputs. New scheme tests go through
  the adapter traits so all eight schemes and both curves run them.
- Coverage comes from tests that reach a branch, never from reshaping code. No comments in code.

## Layout

- `src/group.rs`, `src/group/`: the arkworks wrapper (generator tables, pairing products, linalg, dlog, encoding).
- `src/ipfe/`, `src/qfe/`: one module per scheme with the same function set.
- `tests/`, `benches/schemes.rs`: cases over every scheme and curve, group unit tests, and the benchmarks.
- `.cargo/config.toml` enables `bmi2` and `adx` on x86_64 for ark-ff's assembly, only for builds run from this repo.
