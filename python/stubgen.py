from dataclasses import dataclass
from pathlib import Path

PACKAGE = Path(__file__).parent / "python" / "pfe"
TABLE_TYPES = ("DlogTable", "Gt")


@dataclass(frozen=True)
class Shape:
    public_key: bool
    master_key_methods: tuple[str, ...]
    functions: tuple[str, ...]


IPFE_SEALING = (
    "setup(n: int) -> MasterKey",
    "keygen(msk: MasterKey, function: Sequence[SupportsIndex]) -> Key",
    "encrypt(msk: MasterKey, message: Sequence[SupportsIndex]) -> Ciphertext",
)
PREPARE = "prepare(sk: Key) -> PreparedKey"
TABLE_DECRYPT = "decrypt(table: DlogTable, sk: Key | PreparedKey, ct: Ciphertext) -> int | None"
RANGE_DECRYPT = "decrypt(sk: Key | PreparedKey, ct: Ciphertext, lo: int, hi: int) -> int | None"
BASE = "base() -> Gt"

RANGE = Shape(public_key=False, master_key_methods=(), functions=(*IPFE_SEALING, PREPARE, RANGE_DECRYPT))
TABLE = Shape(public_key=False, master_key_methods=(), functions=(*IPFE_SEALING, PREPARE, TABLE_DECRYPT, BASE))
TABLE_MSK = Shape(
    public_key=False,
    master_key_methods=("base(self) -> Gt",),
    functions=(*IPFE_SEALING, PREPARE, TABLE_DECRYPT),
)
QFE = Shape(
    public_key=True,
    master_key_methods=(),
    functions=(
        "setup(n: int) -> tuple[PublicKey, MasterKey]",
        "keygen(msk: MasterKey, function: Sequence[Sequence[SupportsIndex]]) -> Key",
        "encrypt(pk: PublicKey, left: Sequence[SupportsIndex], right: Sequence[SupportsIndex]) -> Ciphertext",
        PREPARE,
        TABLE_DECRYPT,
        BASE,
    ),
)

SCHEMES = {
    "ipfe": {"bjk": RANGE, "tao": TABLE_MSK, "kim": RANGE, "lin": TABLE, "kks": TABLE, "opt": TABLE},
    "qfe": {"bcfg": QFE, "sgp": QFE},
}


def names_list(names: list[str]) -> str:
    return "__all__ = [\n" + "".join(f'    "{name}",\n' for name in names) + "]"


def encoded_class(name: str, methods: tuple[str, ...]) -> str:
    return "\n".join(
        [
            "@final",
            f"class {name}:",
            f"    def __new__(cls, data: bytes) -> {name}: ...",
            "    @staticmethod",
            f"    def from_bytes(data: bytes) -> {name}: ...",
            "    def __bytes__(self) -> bytes: ...",
            f"    def __reduce__(self) -> tuple[type[{name}], tuple[bytes]]: ...",
            "    @property",
            "    def n(self) -> int: ...",
            *(f"    def {method}: ..." for method in methods),
        ]
    )


PREPARED_KEY = "\n".join(["@final", "class PreparedKey:", "    @property", "    def n(self) -> int: ..."])


def render_scheme(shape: Shape) -> str:
    classes = {
        "MasterKey": encoded_class("MasterKey", shape.master_key_methods),
        "Key": encoded_class("Key", ()),
        "Ciphertext": encoded_class("Ciphertext", ()),
        "PreparedKey": PREPARED_KEY,
        **({"PublicKey": encoded_class("PublicKey", ())} if shape.public_key else {}),
    }
    functions = "".join(f"def {function}: ...\n" for function in shape.functions)
    body = "\n\n".join(classes.values()) + "\n\n" + functions
    table_types = [name for name in TABLE_TYPES if name in body]
    imports = ["from collections.abc import Sequence", "from typing import SupportsIndex, final", ""]
    if table_types:
        imports += [f"from pfe import {', '.join(table_types)}", ""]
    exported = [*classes, *(function.split("(")[0] for function in shape.functions)]
    return "\n".join(imports) + "\n" + names_list(exported) + "\n\n" + body


if __name__ == "__main__":
    for family, schemes in SCHEMES.items():
        folder = PACKAGE / family
        (folder / "__init__.pyi").write_text(f"from . import {', '.join(schemes)}\n\n{names_list(list(schemes))}\n")
        for name, shape in schemes.items():
            (folder / f"{name}.pyi").write_text(render_scheme(shape))
