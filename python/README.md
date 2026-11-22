# Email Header Analyzer

Paquet Python source de vérité pour l'analyse des en-têtes, des liens, du parcours `Received` et du DNS. Il fournit aussi un outil en ligne de commande.

Consulte le [README principal](../README.md) pour les instructions web, la confidentialité et les résultats des exemples.

## Utiliser le CLI

Depuis le dossier `python/` :

```powershell
python -m header_analyzer samples\phishing.eml
```

Le code de sortie `2` indique un verdict de phishing probable. Le CLI fonctionne hors ligne par défaut. Les options `--dns` et `--geoip` sont facultatives.

## Tests

Depuis le dossier `python/` :

```powershell
python -m unittest -v
```

Le paquet déclare Python 3.9 ou plus récent et la licence MIT dans `pyproject.toml`.
