# progetto/__init__.py
"""Pacchetto del generatore di password sicure (CLI)."""

from .secure_password_generator import (
    PasswordPolicy,
    generate_password,
    estimate_entropy_bits,
)

__all__ = ["PasswordPolicy", "generate_password", "estimate_entropy_bits"]
__version__ = "0.1.0"
