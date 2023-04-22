# Redes: TP1 Wiretapping

## Analysis
Se necesita `python3` y `pipenv`

### `sniff.py`
Guarda el .pcap en `./analysis/data` y luego llama a `analyze.py`
```
cd analysis
pipenv install
pipenv run sudo python sniff.py {user} {experiment_name}
```

### `analyze.py`
Si ya se tiene un .pcap, lo analiza y guarda los datos en `./analysis/out/{user}_{experiment_name}`
```
cd analysis
pipenv install
pipenv run python analyze.py {user} {experiment_name} # Pasar --force=True para reemplazar los datos previamente guardados # Pasar --all=True para correr sobre todos los .pcap
```
