from fastapi import FastAPI, Query
from typing import Optional

app = FastAPI(
    title="Mock Vulnerable API",
    description="Une API FastAPI délibérément 'vulnérable' sous forme de bouchon. Les réponses simulent des vulnérabilités courantes (XSS, SQLi, etc.) mais ne sont pas réellement exploitables. Utilisez /docs pour voir l'interface Swagger.",
    version="1.0.0",
)

@app.get("/")
async def root():
    return {"message": "Bienvenue sur l'API mock vulnérable. Consultez /docs pour l'interface."}

@app.get("/echo")
async def echo_input(text: str = Query(..., description="Texte à répéter (simule XSS)")):
    """
    Endpoint qui répète l'entrée utilisateur sans filtrage.
    Simule une vulnérabilité XSS : l'entrée est directement retournée.
    """
    return {"echo": text}  # Simule une injection XSS

@app.get("/user/{user_id}")
async def get_user(user_id: str):
    """
    Récupère les infos d'un utilisateur par ID.
    Simule une vulnérabilité SQLi : accepte des entrées non filtrées.
    """
    # Simule une requête SQL vulnérable
    if "OR 1=1" in user_id.upper():
        return {"user": {"id": "admin", "name": "Admin User", "role": "admin"}}
    elif "DROP TABLE" in user_id.upper():
        return {"error": "Table dropped!"}  # Simule une injection destructive
    else:
        return {"user": {"id": user_id, "name": f"User {user_id}", "role": "user"}}

@app.post("/login")
async def login(username: str, password: str):
    """
    Simule une authentification vulnérable.
    Accepte toujours 'admin'/'admin' pour simuler une faille.
    """
    if username == "admin" and password == "admin":
        return {"token": "fake-jwt-token", "message": "Login réussi (vulnérable)"}
    else:
        return {"error": "Identifiants invalides"}

@app.get("/search")
async def search(query: str = Query(..., description="Requête de recherche")):
    """
    Recherche simulée avec injection possible.
    Retourne des résultats basés sur la requête.
    """
    if "password" in query.lower():
        return {"results": ["Mot de passe trouvé : secret123"]}
    else:
        return {"results": [f"Résultat pour '{query}'"]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9000)
