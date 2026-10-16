from typing import final

from . import ipfe, qfe

__all__ = ["Gt", "DlogTable", "DecodeError", "ipfe", "qfe"]

@final
class Gt: ...

@final
class DlogTable:
    def __new__(cls, base: Gt, lo: int, hi: int) -> DlogTable: ...

class DecodeError(ValueError): ...
