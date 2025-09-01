# partendo dall'immagine python
FROM python

# imposto la worker directory nell'immagine
WORKDIR /app

# copio il file locale .whl creato prima all'interno del container nella WORKDIR indicata con .

COPY dist/*.whl .

# installo il pacchetto request in modo che l'utente non debba farlo manualmente
RUN ["python","-m", "pip", "install", "requests"]

# installo il pacchetto .whl in modo che l'utente non debba farlo manualmente
RUN ["python","-m", "pip", "install", "progetto-0.1.0-py3-none-any.whl"]

# mando in esecuzione l'applicazione in maniera automatica
ENTRYPOINT ["genpw", "--log-level", "WARNING"]