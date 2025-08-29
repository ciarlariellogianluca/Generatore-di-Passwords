#!/usr/bin/env python3
"""Generatore di password sicure (CLI) con logging.

- Usa `secrets` per scelte crittograficamente sicure.
- Garantisce almeno un carattere per ogni categoria selezionata.
- Opzione per escludere caratteri ambigui (O/0, l/1, ecc.).
- Stima l'entropia in bit.
- Usa `logging` con livelli INFO/DEBUG/ERROR.

Esempi:
    # Password di 24 caratteri con ambigui
    python secure_password_generator.py -l 24 --allow-ambiguous

    # 5 password da 20 caratteri
    python secure_password_generator.py -l 20 -c 5

    # Solo lettere e numeri (niente simboli)
    python secure_password_generator.py --no-symbols
"""

from __future__ import annotations

import argparse
import logging
import math
import secrets
import string
from dataclasses import dataclass
from typing import Iterable, List, Sequence

__all__ = [
    "PasswordPolicy",
    "generate_password",
    "estimate_entropy_bits",
    "build_full_pool",
    "build_parser",
    "main",
]

# -----------------------------------------------------------------------------
# Logging (config di default: INFO; passa -v per DEBUG da CLI)
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)
if not logger.handlers:
    # Config minimale: l'utente può alzare il livello con -v/--verbose
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

# -----------------------------------------------------------------------------
# Costanti / configurazione
# -----------------------------------------------------------------------------
MIN_PASSWORD_LENGTH = 4
"""Lunghezza minima accettata per generare una password."""

AMBIGUOUS: set[str] = set("Il1O0o|`~'\" ")
"""Insieme di caratteri considerati ambigui (da escludere se richiesto)."""

DEFAULT_SYMBOLS: str = string.punctuation
"""Set di simboli usati per default (puoi personalizzarlo)."""

_RNG = secrets.SystemRandom()
"""Mescolatore sicuro basato su os.urandom."""


# -----------------------------------------------------------------------------
# Modello di configurazione
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class PasswordPolicy:
    """Imposta quali categorie di caratteri usare e se permettere ambigui."""
    use_lower: bool = True
    use_upper: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    allow_ambiguous: bool = False


# -----------------------------------------------------------------------------
# Funzioni di supporto
# -----------------------------------------------------------------------------
def _filter_ambiguous(chars: str, allow_ambiguous: bool) -> str:
    """Restituisce `chars` filtrando i caratteri ambigui se necessario."""
    if allow_ambiguous:
        return chars
    return "".join(ch for ch in chars if ch not in AMBIGUOUS)


def _non_empty_or_raise(cats: Iterable[str]) -> None:
    """Verifica che tutte le categorie in `cats` siano non vuote."""
    for cat in cats:
        if not cat:
            raise ValueError(
                "Le opzioni scelte hanno svuotato una categoria. "
                "Abilita i caratteri ambigui con --allow-ambiguous oppure "
                "includi più categorie."
            )


def build_full_pool(policy: PasswordPolicy) -> str:
    """Costruisce il pool complessivo di caratteri in base alla policy."""
    parts: List[str] = []
    if policy.use_lower:
        parts.append(_filter_ambiguous(string.ascii_lowercase, policy.allow_ambiguous))
    if policy.use_upper:
        parts.append(_filter_ambiguous(string.ascii_uppercase, policy.allow_ambiguous))
    if policy.use_digits:
        parts.append(_filter_ambiguous(string.digits, policy.allow_ambiguous))
    if policy.use_symbols:
        parts.append(_filter_ambiguous(DEFAULT_SYMBOLS, policy.allow_ambiguous))

    if not parts:
        raise ValueError(
            "Nessuna categoria selezionata: abilita almeno una tra "
            "minuscole/maiuscole/cifre/simboli."
        )

    _non_empty_or_raise(parts)

    pool = "".join(parts)
    pool = "".join(sorted(set(pool)))
    logger.debug("Full pool costruito: %s simboli", len(pool))
    return pool


def _category_pools(policy: PasswordPolicy) -> List[str]:
    """Ritorna i pool per categoria (garantisce 1 char per categoria)."""
    cats: List[str] = []
    if policy.use_lower:
        cats.append(_filter_ambiguous(string.ascii_lowercase, policy.allow_ambiguous))
    if policy.use_upper:
        cats.append(_filter_ambiguous(string.ascii_uppercase, policy.allow_ambiguous))
    if policy.use_digits:
        cats.append(_filter_ambiguous(string.digits, policy.allow_ambiguous))
    if policy.use_symbols:
        cats.append(_filter_ambiguous(DEFAULT_SYMBOLS, policy.allow_ambiguous))
    _non_empty_or_raise(cats)
    logger.debug("Categorie attive: %d", len(cats))
    return cats


def _require_min_length(length: int, min_len: int = MIN_PASSWORD_LENGTH) -> None:
    """Verifica la lunghezza minima richiesta."""
    if length < min_len:
        raise ValueError(f"La lunghezza minima consigliata è {min_len} caratteri.")


# -----------------------------------------------------------------------------
# API principali
# -----------------------------------------------------------------------------
def generate_password(length: int = 16, policy: PasswordPolicy = PasswordPolicy()) -> str:
    """Genera una password rispettando la policy fornita."""
    _require_min_length(length)

    cats = _category_pools(policy)
    full_pool = build_full_pool(policy)

    # 1 char garantito per categoria
    password_chars = [secrets.choice(cat) for cat in cats]

    # Riempi il resto
    remaining = length - len(password_chars)
    password_chars.extend(secrets.choice(full_pool) for _ in range(remaining))

    # Mescola con RNG sicuro
    _RNG.shuffle(password_chars)
    pwd = "".join(password_chars)
    logger.debug(
        "Password generata (len=%d, cats=%d, pool=%d)",
        length,
        len(cats),
        len(full_pool),
    )
    return pwd


def estimate_entropy_bits(length: int, pool_size: int) -> float:
    """Stima l'entropia in bit di una password scelta uniformemente da un pool."""
    if length <= 0 or pool_size <= 1:
        return 0.0
    return length * math.log2(pool_size)


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    """Crea il parser CLI."""
    parser = argparse.ArgumentParser(
        description="Generatore di password sicure (usa 'secrets').",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-l", "--length", type=int, default=16,
                        help="Lunghezza password")
    parser.add_argument("-c", "--count", type=int, default=1,
                        help="Quante password generare")
    parser.add_argument("--no-lower", action="store_true",
                        help="Esclude lettere minuscole")
    parser.add_argument("--no-upper", action="store_true",
                        help="Esclude lettere maiuscole")
    parser.add_argument("--no-digits", action="store_true",
                        help="Esclude cifre")
    parser.add_argument("--no-symbols", action="store_true",
                        help="Esclude simboli")
    parser.add_argument("--allow-ambiguous", action="store_true",
                        help="Permette caratteri ambigui (O/0, l/1, ecc.)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Mostra log di DEBUG (più dettagli)")
    return parser


def _bool(enabled: bool) -> bool:
    """Identità booleana (per rendere esplicito l'intento nel main)."""
    return bool(enabled)


def main(argv: Sequence[str] | None = None) -> None:
    """Entry-point della CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Livello di logging: INFO di default, DEBUG se -v/--verbose
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Modalità verbose attiva (DEBUG).")

    policy = PasswordPolicy(
        use_lower=_bool(not args.no_lower),
        use_upper=_bool(not args.no_upper),
        use_digits=_bool(not args.no_digits),
        use_symbols=_bool(not args.no_symbols),
        allow_ambiguous=args.allow_ambiguous,
    )

    try:
        pool_size = len(build_full_pool(policy))
        logger.info(
            "Generazione di %s password (len=%s, pool=%s, policy=%s)",
            args.count,
            args.length,
            pool_size,
            policy,
        )

        for idx in range(int(args.count)):
            pwd = generate_password(length=int(args.length), policy=policy)
            # INFO: output “utile” all’utente
            logger.info("Password: %s", pwd)

            # DEBUG: dettagli tecnici (solo in verbose)
            if args.count == 1 and idx == 0:
                entropy = estimate_entropy_bits(len(pwd), pool_size)
                logger.debug("Entropia ≈ %.1f bit (pool=%s)", entropy, pool_size)
    except ValueError as err:
        logger.error("Errore: %s", err)
        parser.error(str(err))


if __name__ == "__main__":
    main()
