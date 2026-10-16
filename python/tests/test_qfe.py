import pickle

import pytest

import pfe
from conftest import concurrently, decryptor, round_trip

FUNCTION = [[1, 0, 2], [0, -1, 0], [3, 1, 1]]
CASES = [
    ([1, -2, 3], [4, 5, -6], 35),
    ([-1, 1, 0], [2, 0, 1], -4),
    ([0, 0, 0], [4, 5, -6], 0),
    ([1, 0, 0], [100, 0, 0], 100),
    ([0, 1, 0], [0, 100, 0], -100),
    ([1, 0, 0], [101, 0, 0], None),
    ([0, 1, 0], [0, 101, 0], None),
]


def test_decrypts_quadratic_forms_exactly_within_the_range(qfe):
    pk, msk = qfe.setup(3)
    decrypt = decryptor(qfe, msk, -100, 100)
    sk = qfe.keygen(msk, FUNCTION)
    prepared = qfe.prepare(sk)
    assert (sk.n, prepared.n) == (3, 3)
    cts = [qfe.encrypt(pk, x, y) for x, y, _ in CASES]
    want = [want for _, _, want in CASES]
    assert concurrently(decrypt, sk, cts) == want
    assert concurrently(decrypt, prepared, cts) == want


def test_rejects_inputs_of_the_wrong_shape(qfe):
    pk, msk = qfe.setup(3)
    for f in ([[1, 2], [3, 4], [5, 6]], [[1, 2, 3], [4, 5, 6]]):
        with pytest.raises(ValueError, match="input has 2 entries where 3 are needed"):
            qfe.keygen(msk, f)
    with pytest.raises(ValueError, match="input has 2 entries where 3 are needed"):
        qfe.encrypt(pk, [1, 2], [1, 2, 3])
    with pytest.raises(ValueError, match="input has 4 entries where 3 are needed"):
        qfe.encrypt(pk, [1, 2, 3], [1, 2, 3, 4])


def test_rejects_dimensions_outside_the_encodable_range(qfe):
    with pytest.raises(ValueError, match="input has 0 entries where 1 are needed"):
        qfe.setup(0)
    with pytest.raises(ValueError, match="input has 4294967296 entries where 4294967295 are needed"):
        qfe.setup(2**32)


def test_rejects_mismatched_key_and_ciphertext(qfe):
    pk, msk = qfe.setup(3)
    decrypt = decryptor(qfe, msk, -100, 100)
    sk = qfe.keygen(msk, FUNCTION)
    other_pk, _ = qfe.setup(2)
    ct = qfe.encrypt(other_pk, [1, 2], [3, 4])
    for key in (sk, qfe.prepare(sk)):
        with pytest.raises(ValueError, match="input has 2 entries where 3 are needed"):
            decrypt(key, ct)


def test_encodings_round_trip_and_decrypt(qfe):
    pk, msk = qfe.setup(3)
    restored_pk = round_trip(pk)
    restored_msk = round_trip(msk)
    sk = round_trip(qfe.keygen(restored_msk, FUNCTION))
    ct = round_trip(qfe.encrypt(restored_pk, [1, -2, 3], [4, 5, -6]))
    assert (restored_pk.n, restored_msk.n, sk.n, ct.n) == (3, 3, 3, 3)
    assert decryptor(qfe, restored_msk, -100, 100)(sk, ct) == 35

    pk, msk = qfe.setup(1)
    restored_pk = round_trip(pk)
    restored_msk = round_trip(msk)
    sk = round_trip(qfe.keygen(restored_msk, [[-3]]))
    ct = round_trip(qfe.encrypt(restored_pk, [7], [2]))
    assert decryptor(qfe, restored_msk, -100, 100)(sk, ct) == -42


def test_rejects_corrupt_encodings(qfe):
    pk, _ = qfe.setup(2)
    data = bytes(pk)
    for corrupt in (data[:-1], b"\0\0\0\0" + data[4:]):
        with pytest.raises(pfe.DecodeError) as info:
            qfe.PublicKey(corrupt)
        assert isinstance(info.value, ValueError)


def test_prepared_key_is_not_picklable(qfe):
    _, msk = qfe.setup(1)
    prepared = qfe.prepare(qfe.keygen(msk, [[1]]))
    with pytest.raises(TypeError):
        pickle.dumps(prepared)
    with pytest.raises(TypeError):
        bytes(prepared)
