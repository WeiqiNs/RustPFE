import pickle
from concurrent.futures import ThreadPoolExecutor

import pytest

import pfe
from pfe.ipfe import bjk, kim, kks, lin, opt, tao
from pfe.qfe import bcfg, sgp

IPFE = [bjk, tao, kim, lin, kks, opt]
QFE = [bcfg, sgp]
RANGE = (bjk, kim)


def short_name(scheme):
    return scheme.__name__.rsplit(".", 1)[-1]


@pytest.fixture(params=IPFE, ids=short_name)
def ipfe(request):
    return request.param


@pytest.fixture(params=QFE, ids=short_name)
def qfe(request):
    return request.param


def decryptor(scheme, msk, lo, hi):
    if scheme in RANGE:
        return lambda sk, ct: scheme.decrypt(sk, ct, lo, hi)
    base = msk.base() if scheme is tao else scheme.base()
    table = pfe.DlogTable(base, lo, hi)
    return lambda sk, ct: scheme.decrypt(table, sk, ct)


def concurrently(decrypt, sk, cts):
    with ThreadPoolExecutor(max_workers=len(cts)) as pool:
        return list(pool.map(lambda ct: decrypt(sk, ct), cts))


def round_trip(value):
    data = bytes(value)
    assert bytes(type(value).from_bytes(data)) == data
    unpickled = pickle.loads(pickle.dumps(value))
    assert bytes(unpickled) == data
    return unpickled
