# Generatore di Password Sicure

Questa applicazione, scritta in Python, permette di generare password sicure utilizzando il modulo `secrets` 
per garantire un alto livello di casualità crittografica.

### Funzionalità
- Generazione di password robuste con lettere maiuscole, minuscole, numeri e simboli.
- Possibilità di escludere caratteri ambigui (es. O/0, l/1).
- Stima dell’entropia (in bit) delle password generate.
- Supporto a più password in un singolo comando.
- Completamente utilizzabile da riga di comando (CLI).

### Esempi di utilizzo
Genera una password lunga 16 caratteri (default):
```bash
python3 secure_password_generator.py
# Generatore-di-Passwords
