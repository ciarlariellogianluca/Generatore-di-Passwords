# Generatore di Password Sicure

Questa applicazione, scritta in Python, genera password robuste utilizzando il modulo `secrets`, garantendo un alto livello di casualità crittografica.

## ✨ Funzionalità
- Generazione di password con lettere maiuscole, minuscole, cifre e simboli.
- Possibilità di escludere caratteri ambigui (es. `O/0`, `l/1`).
- Garanzia di almeno un carattere per ogni categoria attiva.
- Stima dell’entropia (in bit) delle password generate.
- Supporto alla generazione multipla (`--count`).
- Completamente utilizzabile da riga di comando (CLI) o come libreria Python.
- Container Docker pronto per l’uso.

## 📦 Installazione

### Da sorgente
```bash
git clone https://github.com/TUO_USER/progetto.git
cd progetto
pip install .
Da pacchetto (wheel/sdist)
bash
Copia codice
pip install dist/progetto-0.1.0-py3-none-any.whl
Da Docker
bash
Copia codice
docker build -t genpw .
docker run --rm genpw -l 20 -c 3

 Utilizzo CLI
Genera una password di 16 caratteri (default):

bash
Copia codice
genpw
Genera 5 password di 20 caratteri:

bash
Copia codice
genpw -l 20 -c 5
Escludi i simboli:

bash
Copia codice
genpw --no-symbols
Permetti caratteri ambigui:

bash
Copia codice
genpw -l 24 --allow-ambiguous
Attiva modalità verbosa (log di debug):

bash
Copia codice
genpw -l 16 -v

🐳 Docker
Esegui direttamente da container:

bash
Copia codice
docker run --rm tuousername/genpw:latest -l 24 -c 3