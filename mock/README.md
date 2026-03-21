# Mock Vulnerable API

Ce dossier contient une API FastAPI délibérément "vulnérable" sous forme de bouchon. Elle simule des vulnérabilités courantes (XSS, SQLi, etc.) via des réponses qui laissent entendre des failles, mais n'est pas réellement exploitable.

## Endpoints

- `GET /` : Accueil
- `GET /echo?text=...` : Répète l'entrée (simule XSS)
- `GET /user/{user_id}` : Infos utilisateur (simule SQLi)
- `POST /login` : Authentification vulnérable
- `GET /search?query=...` : Recherche avec injection possible

## Lancement

```bash
cd mock
python mock_api.py
```

L'API sera accessible sur http://localhost:9000.

## Swagger UI

Consultez l'interface Swagger à http://localhost:9000/docs pour voir le contrat d'interface.

## Note

Toutes les "vulnérabilités" sont simulées et inoffensives. Utilisez uniquement pour des tests ou démonstrations.