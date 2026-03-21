from flask import Flask, send_from_directory, redirect
import os

app = Flask(__name__)

# Chemin vers le dossier static
STATIC_DIR = os.path.join(os.path.dirname(__file__), 'static')

@app.route('/')
def index():
    """Redirige la racine vers webapp.html"""
    return redirect('/webapp.html')

@app.route('/<path:filename>')
def serve_static(filename):
    """Sert les fichiers statiques depuis le dossier static/"""
    try:
        return send_from_directory(STATIC_DIR, filename)
    except FileNotFoundError:
        return "File not found", 404

if __name__ == '__main__':
    port = 8800
    print(f"Serving static/ at http://localhost:{port}")
    app.run(host='127.0.0.1', port=port, debug=False)