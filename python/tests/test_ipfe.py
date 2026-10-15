import pickle

import pytest

import pfe
from conftest import concurrently, decryptor, round_trip
from pfe.ipfe import bjk, opt

CASES = [
    ([5, 6, 7, 8], 46),
    ([-4, 5, -6, 0], -32),
    ([2, 1, 0, 0], 0),
    ([0, 0, 0, 25], 100),
    ([0, 0, 0, -25], -100),
    ([1, 0, 0, 25], None),
    ([-1, 0, 0, -25], None),
]


def test_decrypts_inner_products_exactly_within_the_range(ipfe):
    msk = ipfe.setup(4)
    decrypt = decryptor(ipfe, msk, -100, 100)
    sk = ipfe.keygen(msk, [1, -2, 3, 4])
    prepared = ipfe.prepare(sk)
    assert (sk.n, prepared.n) == (4, 4)
    cts = [ipfe.encrypt(msk, x) for x, _ in CASES]
    want = [want for _, want in CASES]
    assert concurrently(decrypt, sk, cts) == want
    assert concurrently(decrypt, prepared, cts) == want


def test_rejects_vectors_of_the_wrong_length(ipfe):
    msk = ipfe.setup(4)
    for v in [[1, 2, 3], [1, 2, 3, 4, 5]]:
        message = f"input has {len(v)} entries where 4 are needed"
        for call in (ipfe.keygen, ipfe.encrypt):
            with pytest.raises(ValueError, match=message) as info:
                call(msk, v)
            assert not isinstance(info.value, pfe.DecodeError)


def test_rejects_dimensions_outside_the_encodable_range(ipfe):
    with pytest.raises(ValueError, match="input has 0 entries where 1 are needed"):
        ipfe.setup(0)
    with pytest.raises(ValueError, match="input has 4294967296 entries where 4294967295 are needed"):
        ipfe.setup(2**32)


def test_rejects_integers_outside_i64():
    msk = opt.setup(4)
    with pytest.raises(OverflowError):
        opt.keygen(msk, [2**63, 0, 0, 0])
    with pytest.raises(OverflowError):
        opt.setup(-1)


def test_rejects_mismatched_key_and_ciphertext(ipfe):
    msk = ipfe.setup(4)
    decrypt = decryptor(ipfe, msk, -100, 100)
    sk = ipfe.keygen(msk, [1, -2, 3, 4])
    ct = ipfe.encrypt(ipfe.setup(3), [1, 2, 3])
    for key in (sk, ipfe.prepare(sk)):
        with pytest.raises(ValueError, match="input has 3 entries where 4 are needed"):
            decrypt(key, ct)


def test_rejects_keys_of_another_scheme(ipfe):
    other = bjk if ipfe is opt else opt
    msk = ipfe.setup(4)
    decrypt = decryptor(ipfe, msk, -100, 100)
    ct = ipfe.encrypt(msk, [5, 6, 7, 8])
    foreign = other.keygen(other.setup(4), [1, -2, 3, 4])
    with pytest.raises(TypeError):
        decrypt(foreign, ct)


def test_encodings_round_trip_and_decrypt(ipfe):
    msk = ipfe.setup(4)
    restored = round_trip(msk)
    sk = round_trip(ipfe.keygen(restored, [1, -2, 3, 4]))
    ct = round_trip(ipfe.encrypt(msk, [5, 6, 7, 8]))
    assert (restored.n, sk.n, ct.n) == (4, 4, 4)
    assert decryptor(ipfe, restored, -100, 100)(sk, ct) == 46

    msk = ipfe.setup(1)
    restored = round_trip(msk)
    sk = round_trip(ipfe.keygen(restored, [-3]))
    ct = round_trip(ipfe.encrypt(msk, [7]))
    assert decryptor(ipfe, restored, -100, 100)(sk, ct) == -21


def test_rejects_corrupt_encodings(ipfe):
    data = bytes(ipfe.keygen(ipfe.setup(2), [1, 2]))
    for corrupt in (data[:-1], data + b"\0", b"\0\0\0\0" + data[4:]):
        with pytest.raises(pfe.DecodeError) as info:
            ipfe.Key.from_bytes(corrupt)
        assert isinstance(info.value, ValueError)


def test_prepared_key_is_not_picklable(ipfe):
    prepared = ipfe.prepare(ipfe.keygen(ipfe.setup(1), [1]))
    with pytest.raises(TypeError):
        pickle.dumps(prepared)
    with pytest.raises(TypeError):
        bytes(prepared)
