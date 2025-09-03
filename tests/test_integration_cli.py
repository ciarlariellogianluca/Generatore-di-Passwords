import logging
import pytest

from progetto.secure_password_generator import main, DEFAULT_SYMBOLS
# se lavori fuori dal package:
# from secure_password_generator import main, DEFAULT_SYMBOLS


def test_cli_generates_count_and_length(capsys):
    main(["-l", "12", "-c", "3", "--no-symbols"])
    captured = capsys.readouterr()
    pwds = [line for line in captured.out.strip().splitlines() if line]

    assert len(pwds) == 3
    assert all(len(p) == 12 for p in pwds)
    assert all(all(ch not in DEFAULT_SYMBOLS for ch in p) for p in pwds)


def test_cli_verbose_emits_debug(caplog):
    # In verbose, i messaggi DEBUG sono log (intercettati da pytest)
    caplog.set_level(logging.DEBUG)
    main(["-l", "12", "-c", "1", "-v"])
    text = caplog.text
    assert ("Entropia" in text) or ("Modalità verbose attiva" in text) or ("DEBUG" in text)


def test_cli_errors_when_no_categories_selected(capsys):
    with pytest.raises(SystemExit):
        main(["--no-lower", "--no-upper", "--no-digits", "--no-symbols"])
    err = capsys.readouterr().err
    assert ("Nessuna categoria selezionata" in err) or ("Le opzioni scelte" in err)
