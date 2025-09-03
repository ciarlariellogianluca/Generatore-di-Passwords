"""Pacchetto del generatore di password sicure (CLI e API)."""

from .secure_password_generator import (
    PasswordPolicy,
    generate_password,
    estimate_entropy_bits,
)

__all__ = ["PasswordPolicy", "generate_password", "estimate_entropy_bits", "main"]

# importiamo l'entry point CLI dal modulo interno
from . import secure_password_generator as _spg

def main(argv=None) -> None:
    """Entry point CLI del pacchetto: delega al main del modulo interno."""
    _spg.main(argv)

# Mantieni la versione del pacchetto
__version__ = "0.1.0"
