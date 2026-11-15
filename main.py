"""API FastAPI du TP DevSecOps (cible du pipeline CI/CD securise)."""
import hashlib
import ipaddress
import os
import re
import secrets
import socket
import sqlite3
import subprocess

import requests
import yaml
from fastapi import FastAPI, Header, HTTPException

# Le secret est lu depuis l'environnement (plus de secret en dur, B105)
SECRET_KEY = os.environ.get("SECRET_KEY", "")
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")

DB_PATH = "app.db"

app = FastAPI()


@app.middleware("http")
async def security_headers(request, call_next):
    """En-tetes de securite HTTP ajoutes a toutes les reponses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "name TEXT NOT NULL, "
        "password TEXT NOT NULL)"
    )
    return conn


@app.get("/user")
def get_user(name: str):
    conn = get_db()
    rows = conn.execute(
        "SELECT id, name FROM users WHERE name = ?", (name,)
    ).fetchall()
    conn.close()
    return {"users": [{"id": r[0], "name": r[1]} for r in rows]}


@app.get("/ping")
def ping(host: str):
    # Validation stricte de l'entree : IP ou nom d'hote uniquement
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not HOSTNAME_RE.match(host) or host.startswith("-"):
            raise HTTPException(status_code=400, detail="host invalide")
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise HTTPException(status_code=503, detail="ping indisponible")
    return {"returncode": result.returncode, "output": result.stdout}


@app.post("/register")
def register(name: str, password: str):
    # PBKDF2-HMAC-SHA256 avec sel aleatoire (remplace MD5, B324)
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    hashed = salt.hex() + "$" + digest.hex()
    conn = get_db()
    conn.execute(
        "INSERT INTO users (name, password) VALUES (?, ?)", (name, hashed)
    )
    conn.commit()
    conn.close()
    return {"status": "registered", "name": name}


@app.post("/config")
def load_config(data: str):
    # safe_load : pas d'instanciation d'objets Python arbitraires (B506)
    try:
        config = yaml.safe_load(data)
    except yaml.YAMLError:
        # Pas de stacktrace renvoyee au client : erreur 400 generique
        raise HTTPException(status_code=400, detail="YAML invalide")
    return {"config": config}


@app.get("/fetch")
def fetch(url: str):
    # Verification TLS activee (comportement par defaut, B501)
    if not url.startswith("https://"):
        raise HTTPException(status_code=400, detail="seul https est autorise")
    try:
        r = requests.get(url, timeout=5)
    except requests.RequestException:
        raise HTTPException(status_code=502, detail="URL injoignable")
    return {"status_code": r.status_code, "body": r.text[:500]}


@app.get("/diagnostic/dns")
def dns_lookup(domain: str, x_api_key: str = Header(default="")):
    # Route reservee au support : authentification par cle d'API
    if not SECRET_KEY or not secrets.compare_digest(x_api_key, SECRET_KEY):
        raise HTTPException(status_code=401, detail="authentification requise")
    # Validation stricte + resolution via la bibliotheque standard (aucun shell)
    if not HOSTNAME_RE.match(domain) or domain.startswith("-"):
        raise HTTPException(status_code=400, detail="domaine invalide")
    try:
        addresses = sorted({info[4][0] for info in socket.getaddrinfo(domain, None)})
    except socket.gaierror:
        raise HTTPException(status_code=404, detail="domaine introuvable")
    return {"domain": domain, "addresses": addresses}
