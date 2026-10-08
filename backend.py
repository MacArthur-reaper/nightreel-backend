"""
NightReel backend.   pip install fastapi uvicorn httpx
Run locally:  uvicorn backend:app --reload
On Render/Railway: start command  uvicorn backend:app --host 0.0.0.0 --port $PORT

Env vars:
  ALLOWED_ORIGIN  your site address, e.g. https://yourname.github.io  (default "*")
  BLOCK_VPN       "1" (default) to block VPN/proxy/hosting IPs, "0" to disable
"""
import os
import re
import sqlite3
import time
import urllib.parse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

DB = os.environ.get("DB_PATH", "nightreel.db")
BLOCK_VPN = os.environ.get("BLOCK_VPN", "1") == "1"
COLLECTIONS = "prelinger OR feature_films OR animationandcartoons OR classic_tv OR opensource_movies"

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=[os.environ.get("ALLOWED_ORIGIN", "*")],
                   allow_methods=["GET", "POST"], allow_headers=["*"])


def db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS audit(t INT, ip TEXT, event TEXT, detail TEXT)")
    con.execute("CREATE TABLE IF NOT EXISTS users(email TEXT PRIMARY KEY, t INT, ip TEXT)")
    return con


def client_ip(req: Request):
    fwd = req.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() or req.client.host


def log(ip, event, detail=""):
    with db() as con:
        con.execute("INSERT INTO audit VALUES(?,?,?,?)", (int(time.time()), ip, event, detail[:300]))


_vpn_cache = {}


async def guard(req: Request):
    """Block VPN / proxy / datacenter IPs. Not 100% accurate: some real users may be blocked."""
    ip = client_ip(req)
    if not BLOCK_VPN:
        return ip
    hit = _vpn_cache.get(ip)
    if hit is None or time.time() - hit[1] > 3600:
        bad = False
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                # free tier is for non-commercial use; use a paid plan or another IP-reputation API if commercial
                r = await c.get(f"http://ip-api.com/json/{ip}?fields=status,proxy,hosting")
                j = r.json()
                bad = j.get("status") == "success" and j.get("proxy")
        except Exception:
            bad = False  # if the check fails, let the visitor through
        hit = _vpn_cache[ip] = (bool(bad), time.time())
    if hit[0]:
        log(ip, "blocked_vpn")
        raise HTTPException(403, "VPN or proxy detected")
    return ip


@app.get("/search")
async def search(q: str, req: Request):
    ip = await guard(req)
    q = re.sub(r"[^\w\s'\-]", " ", q)[:80].strip()
    if not q:
        raise HTTPException(400, "Enter a search term")
    log(ip, "search", q)
    params = {"q": f"({q}) AND mediatype:movies AND collection:({COLLECTIONS})",
              "fl[]": ["identifier", "title", "year"], "rows": 20, "output": "json"}
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get("https://archive.org/advancedsearch.php", params=params)
    docs = r.json().get("response", {}).get("docs", [])
    return {"results": [{"id": d["identifier"], "title": d.get("title", d["identifier"]),
                         "year": d.get("year", "")} for d in docs]}


@app.get("/resolve")
async def resolve(id: str, req: Request):
    ip = await guard(req)
    if not re.fullmatch(r"[A-Za-z0-9._\-]+", id):
        raise HTTPException(400, "Bad id")
    async with httpx.AsyncClient(timeout=15) as c:
        meta = (await c.get(f"https://archive.org/metadata/{id}")).json()
    mp4 = [f["name"] for f in meta.get("files", [])
           if f.get("name", "").lower().endswith(".mp4") and "thumb" not in f["name"].lower()]
    if not mp4:
        raise HTTPException(404, "No downloadable video file for this title")
    log(ip, "resolve", id)
    return {"url": f"https://archive.org/download/{id}/{urllib.parse.quote(mp4[0])}"}


@app.post("/register")
async def register(body: dict, req: Request):
    ip = await guard(req)
    email = str(body.get("email", "")).strip().lower()
    if not body.get("consent"):
        raise HTTPException(400, "Consent is required")
    if not re.fullmatch(r"[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}", email) or len(email) > 120:
        raise HTTPException(400, "Enter a valid email address")
    with db() as con:
        con.execute("INSERT OR IGNORE INTO users VALUES(?,?,?)", (email, int(time.time()), ip))
    log(ip, "register")
    return {"ok": True}


@app.post("/audit")
async def audit(body: dict, req: Request):
    """Receives start/done/error events from the desktop app (no file content)."""
    log(client_ip(req), "app_" + str(body.get("event", ""))[:20], str(body.get("url", "")))
    return {"ok": True}
