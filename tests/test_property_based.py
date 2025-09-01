import string
from hypothesis import given, strategies as st
import pytest

from progetto.secure_password_generator import (
    PasswordPolicy,
    generate_password,
    build_full_pool,
    MIN_PASSWORD_LENGTH,
    AMBIGUOUS,
    DEFAULT_SYMBOLS,
)

def st_policy(at_least_one=True):
    base = st.fixed_dictionaries({
        "use_lower": st.booleans(),
        "use_upper": st.booleans(),
        "use_digits": st.booleans(),
        "use_symbols": st.booleans(),
        "allow_ambiguous": st.booleans(),
    })
    if not at_least_one:
        return base.map(lambda d: PasswordPolicy(**d))
    def ensure_one(d):
        if not (d["use_lower"] or d["use_upper"] or d["use_digits"] or d["use_symbols"]):
            d["use_lower"] = True
        return PasswordPolicy(**d)
    return base.map(ensure_one)

@given(st_policy(at_least_one=True))
def test_pool_has_no_duplicates_and_respects_ambiguity(policy):
    pool = build_full_pool(policy)
    assert len(pool) == len(set(pool))
    if not policy.allow_ambiguous:
        assert all(ch not in AMBIGUOUS for ch in pool)

@given(st.integers(min_value=MIN_PASSWORD_LENGTH, max_value=64), st_policy(at_least_one=True))
def test_generated_password_length_and_charset(length, policy):
    pwd = generate_password(length=length, policy=policy)
    pool = set(build_full_pool(policy))
    assert len(pwd) == length
    assert set(pwd) <= pool

@given(st.integers(min_value=MIN_PASSWORD_LENGTH, max_value=64), st_policy(at_least_one=True))
def test_at_least_one_per_enabled_category(length, policy):
    pwd = generate_password(length, policy)
    def filt(s):
        return [ch for ch in s if policy.allow_ambiguous or ch not in AMBIGUOUS]
    if policy.use_lower:
        assert any(ch in filt(string.ascii_lowercase) for ch in pwd)
    if policy.use_upper:
        assert any(ch in filt(string.ascii_uppercase) for ch in pwd)
    if policy.use_digits:
        assert any(ch in filt(string.digits) for ch in pwd)
    if policy.use_symbols:
        assert any(ch in filt(DEFAULT_SYMBOLS) for ch in pwd)

def test_pool_raises_when_all_disabled():
    with pytest.raises(ValueError):
        build_full_pool(PasswordPolicy(False, False, False, False, False))
