import logging
import pytest

# se il modulo è dentro il package "progetto", usa questo import:
from progetto.secure_password_generator import main, DEFAULT_SYMBOLS, AMBIGUOUS
# se invece sei al root con un file shim, cambia in:
# from secure_password_generator import main, DEFAULT_SYMBOLS, AMBIGUOUS

def _parse_pwds(text: str):
    return [line.split("Password:", 1)[1].strip()
            for line in text.splitlines() if "Password:" in line]

def test_cli_generates_count_and_length(caplog):
    caplog.set_level(logging.INFO)
    main(["-l", "12", "-c", "3", "--no-symbols"])
    text = caplog.text
    pwds = _parse_pwds(text)
    assert len(pwds) == 3
    assert all(len(p) == 12 for p in pwds)
    # niente simboli se --no-symbols
    assert all(all(ch not in DEFAULT_SYMBOLS for ch in p) for p in pwds)

def test_cli_verbose_emits_debug(caplog):
    caplog.set_level(logging.DEBUG)
    main(["-l", "12", "-c", "1", "-v"])
    text = caplog.text
    # in verbose dovremmo vedere messaggi DEBUG; accettiamo "Entropia" o il banner verbose
    assert ("Entropia" in text) or ("Modalità verbose attiva" in text) or ("DEBUG" in text)

def test_cli_errors_when_no_categories_selected(capsys):
    # questo rimane con capsys perché argparse.error fa sys.exit(2) e scrive su stderr
    with pytest.raises(SystemExit):
        main(["--no-lower", "--no-upper", "--no-digits", "--no-symbols"])
    err = capsys.readouterr().err
    assert "Nessuna categoria selezionata" in err or "Le opzioni scelte" in err
