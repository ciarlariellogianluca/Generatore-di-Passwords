import math
import string
import pytest

from progetto.secure_password_generator import (
    PasswordPolicy,
    generate_password,
    build_full_pool,
    estimate_entropy_bits,
    MIN_PASSWORD_LENGTH,
    AMBIGUOUS,
    DEFAULT_SYMBOLS,
)

def _filtered(s, allow=False):
    return "".join(ch for ch in s if allow or ch not in AMBIGUOUS)

def test_build_full_pool_includes_categories_and_no_duplicates():
    pol = PasswordPolicy(True, True, True, True, allow_ambiguous=False)
    pool = build_full_pool(pol)
    assert len(pool) == len(set(pool))                # no duplicati
    assert all(ch not in AMBIGUOUS for ch in pool)    # niente ambigui
    # contiene ogni categoria
    assert set(_filtered(string.ascii_lowercase)) <= set(pool)
    assert set(_filtered(string.ascii_uppercase)) <= set(pool)
    assert set(_filtered(string.digits)) <= set(pool)
    assert set(_filtered(DEFAULT_SYMBOLS)) <= set(pool)

def test_build_full_pool_raises_if_no_categories():
    with pytest.raises(ValueError):
        build_full_pool(PasswordPolicy(False, False, False, False, False))

def test_generate_password_respects_length_and_pool():
    pol = PasswordPolicy(True, False, True, False, allow_ambiguous=False)
    pwd = generate_password(16, pol)
    assert len(pwd) == 16
    assert set(pwd) <= set(build_full_pool(pol))

def test_generate_password_requires_min_length():
    with pytest.raises(ValueError):
        generate_password(MIN_PASSWORD_LENGTH - 1, PasswordPolicy())

@pytest.mark.parametrize("length,pool,expected", [
    (0, 10, 0.0),
    (10, 1, 0.0),
    (10, 2, 10.0),  # 10 * log2(2)
    (8, 4, 16.0),   # 8 * log2(4)
])
def test_estimate_entropy_bits_basic(length, pool, expected):
    assert math.isclose(estimate_entropy_bits(length, pool), expected, rel_tol=1e-9)
