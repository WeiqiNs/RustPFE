import pickle

import pytest

import pfe
from pfe.ipfe import bjk, kks, lin, opt
from pfe.qfe import bcfg, sgp


def test_rejects_inverted_bounds():
    with pytest.raises(ValueError, match="dlog: a table needs lo <= hi"):
        pfe.DlogTable(opt.base(), 1, 0)
    msk = bjk.setup(1)
    with pytest.raises(ValueError, match="dlog: a table needs lo <= hi"):
        bjk.decrypt(bjk.keygen(msk, [1]), bjk.encrypt(msk, [1]), 1, 0)


def test_rejects_ranges_too_wide_to_table():
    with pytest.raises(ValueError, match="dlog: a range may span at most"):
        pfe.DlogTable(opt.base(), -(2**40), 1)
    msk = bjk.setup(1)
    with pytest.raises(ValueError, match="dlog: a range may span at most"):
        bjk.decrypt(bjk.keygen(msk, [1]), bjk.encrypt(msk, [1]), -(2**63), 2**63 - 1)


def test_table_is_not_picklable():
    with pytest.raises(TypeError):
        pickle.dumps(pfe.DlogTable(opt.base(), 0, 1))


def test_one_table_serves_every_generator_based_scheme():
    table = pfe.DlogTable(opt.base(), -100, 100)
    for scheme in (opt, lin, kks):
        msk = scheme.setup(2)
        assert scheme.decrypt(table, scheme.keygen(msk, [1, 2]), scheme.encrypt(msk, [3, -4])) == -5
    for scheme in (bcfg, sgp):
        pk, msk = scheme.setup(2)
        sk = scheme.keygen(msk, [[1, 0], [0, 1]])
        assert scheme.decrypt(table, sk, scheme.encrypt(pk, [3, 4], [5, -6])) == -9
