#!/usr/bin/env python3
"""Local administrator setup for GASLUX. No credentials in Git or stdout."""
import argparse
import base64
import fcntl
import hmac
import html
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, quote, urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError

REPO = "LMhdez/gaslux"
ROOT = Path.home() / ".local/state/gaslux-review-apps"
PERMS = {"metadata": "read", "contents": "read", "pull_requests": "write",
         "actions": "read", "checks": "read", "issues": "read"}
ROLES = ("mint", "zorin", "cachyos", "popos", "q4os", "bazzite")

def gh(*args, data=None, missing=False):
    p = subprocess.run(["gh", *args], input=data, capture_output=True, timeout=120)
    if p.returncode:
        if missing and b"HTTP 404" in p.stderr:
            return None
        raise RuntimeError("gh failed: " + " ".join(args[:2]))
    return p.stdout.decode().strip()

def api(path, method="GET", token=None, body=None):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "GASLUX-setup",
               "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = Request("https://api.github.com" + path, method=method, headers=headers,
                      data=json.dumps(body).encode() if body is not None else None)
    try:
        with urlopen(request, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except HTTPError as e:
        if method == "GET" and e.code == 404:
            return None
        raise RuntimeError(f"GitHub API HTTP {e.code} ({method})") from None

def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")

def jwt(app, key):
    now = int(time.time())
    message = b".".join((b64(b'{"alg":"RS256","typ":"JWT"}'),
                         b64(json.dumps({"iat": now-60, "exp": now+480,
                                         "iss": app["client_id"]}).encode())))
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key)],
                         input=message, capture_output=True, check=True).stdout
    return (message + b"." + b64(sig)).decode()

def register(role, bind, port):
    path, key = ROOT / (role + ".json"), ROOT / (role + ".pem")
    if path.exists() and key.exists():
        return json.loads(path.read_text()), key
    if path.exists() or key.exists():
        raise RuntimeError("Incomplete local state: do not register a duplicate App")
    state, route, received = secrets.token_urlsafe(32), secrets.token_urlsafe(24), {}
    origin = f"http://{bind}:{port}"
    # Loopback is safest: use phone SSH port forwarding when available.
    # Private LAN mode is only for a trusted network. The callback code
    # is one-time, and the server is stopped immediately after receiving it.
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def page(self, status, message):
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(message.encode())
        def do_GET(self):
            if self.headers.get("Host") != f"{bind}:{port}":
                return self.page(400, "Invalid host")
            url = urlsplit(self.path)
            if url.path == "/" + route:
                manifest = {"name": "gaslux-independent-" + role,
                            "url": "https://github.com/" + REPO,
                            "description": "GASLUX independent " + role + " reviewer",
                            "public": False,
                            "hook_attributes": {"active": False, "url": "https://github.com/" + REPO},
                            "redirect_url": origin + "/callback",
                            "default_permissions": {k:v for k,v in PERMS.items() if k != "metadata"},
                            "default_events": [], "request_oauth_on_install": False}
                encoded = html.escape(json.dumps(manifest), quote=True)
                return self.page(200, '<meta charset="utf-8"><h2>GASLUX ' + role +
                    '</h2><form id="f" method="post" action="https://github.com/settings/apps/new?state=' +
                    state + '"><input type="hidden" name="manifest" value="' + encoded +
                    '"><button>Continuar para GitHub</button></form>'
                    '<script>document.getElementById("f").submit()</script>')
            if url.path == "/callback":
                q = parse_qs(url.query)
                code = q.get("code", [""])[0]
                if not hmac.compare_digest(q.get("state", [""])[0], state) or not code or "code" in received:
                    return self.page(400, "Invalid callback")
                received["code"] = code
                return self.page(200, "Registo recebido. Continua no terminal do Pi.")
            return self.page(404, "Not found")
    with HTTPServer((bind, port), Handler) as server:
        server.timeout = 1
        print("\nAbre no telemovel: " + origin + "/" + route, flush=True)
        deadline = time.monotonic() + 900
        while "code" not in received and time.monotonic() < deadline:
            server.handle_request()
    if "code" not in received:
        raise RuntimeError("Registration not confirmed; check GitHub before retrying")
    app = api("/app-manifests/" + quote(received["code"], safe="") + "/conversions",
              method="POST", body={})
    private_write(key, app["pem"].encode())
    data = {k:app[k] for k in ("id", "slug", "client_id", "owner", "permissions")}
    data["public"] = app.get("public", False)
    private_write(path, json.dumps(data).encode())
    return data, key

def install(app, key):
    live = api("/app", token=jwt(app, key))
    if (not live or live.get("id") != app["id"] or live.get("client_id") != app["client_id"]
            or live.get("slug") != app["slug"] or live.get("public") is True
            or app.get("public") is True
            or live.get("owner", {}).get("login", "").lower() != "lmhdez"
            or live.get("permissions") != PERMS):
        raise RuntimeError("App identity/private permissions not verified")
    if live.get("public") is None:
        # GitHub may omit visibility; a private manifest is not live proof.
        # Reject a publicly accessible app before continuing.
        if api("/apps/" + quote(app["slug"], safe="")) is not None:
            raise RuntimeError("App is publicly accessible; verify private registration")
        print("App not publicly accessible; identity and permissions verified.", flush=True)
    def find():
        return api("/repos/" + REPO + "/installation", token=jwt(app, key))
    inst = find()
    if inst is None:
        print("Instala apenas em gaslux (Only select repositories):\nhttps://github.com/apps/" +
              quote(app["slug"], safe="") + "/installations/new", flush=True)
        deadline = time.monotonic() + 900
        while inst is None and time.monotonic() < deadline:
            time.sleep(3)
            inst = find()
    if (not inst or inst.get("app_id") != app["id"] or inst.get("repository_selection") != "selected"
            or inst.get("account", {}).get("login", "").lower() != "lmhdez"
            or inst.get("permissions") != PERMS or inst.get("suspended_at")):
        raise RuntimeError("Installation not verified; select only gaslux and retry")
    installations = api("/app/installations?per_page=100", token=jwt(app, key))
    if (not isinstance(installations, list) or len(installations) != 1
            or installations[0].get("id") != inst["id"]):
        raise RuntimeError("Unexpected additional App installations")
    response = api(f"/app/installations/{inst['id']}/access_tokens", method="POST",
                   token=jwt(app,key), body={"repositories":["gaslux"],
                   "permissions":{k:v for k,v in PERMS.items() if k != "metadata"}})
    token = response["token"]
    try:
        repos = api("/installation/repositories?per_page=100", token=token)
        if (repos.get("total_count") != 1 or len(repos.get("repositories", [])) != 1
                or repos["repositories"][0]["full_name"].lower() != REPO.lower()):
            raise RuntimeError("Installation token exceeds repository scope")
        bot = api("/users/" + quote(app["slug"] + "[bot]", safe=""), token=token)
        if (not bot or bot.get("type") != "Bot" or bot.get("login") != app["slug"] + "[bot]"
                or type(bot.get("id")) is not int or bot["id"] <= 0):
            raise RuntimeError("Bot identity not verified")
        return bot["id"]
    finally:
        api("/installation/token", method="DELETE", token=token)

def variables():
    return {v["name"]:v["value"] for v in json.loads(gh("variable", "list", "-R", REPO,
                                                       "--json", "name,value"))}
def setvar(name, value):
    gh("variable", "set", name, "-R", REPO, "--body", value)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1", help="Loopback or explicit trusted private LAN IPv4")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    address = ipaddress.ip_address(args.bind)
    tailnet = False
    if address.version == 4 and address in ipaddress.ip_network("100.64.0.0/10"):
        try:
            actual = subprocess.run(["tailscale", "ip", "-4"], check=True,
                                    capture_output=True, text=True, timeout=10).stdout.splitlines()
            tailnet = str(address) in actual
        except (OSError, subprocess.SubprocessError):
            pass
    if (address.version != 4 or not 1024 <= args.port <= 65535 or
            not (tailnet or address.is_loopback or any(address in ipaddress.ip_network(n)
                       for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))):
        raise RuntimeError("Use loopback, private LAN IPv4, or the actual Tailscale IPv4")
    if tailnet:
        print("Tailscale: liga o telemovel a mesma tailnet. Nao exponhas a porta na Internet.", flush=True)
    elif not address.is_loopback:
        print("ATENCAO: usa apenas Wi-Fi/LAN privada de confianca. Callback HTTP local; nunca exponhas a porta na Internet.", flush=True)
    os.umask(0o077)
    if gh("api", "user", "--jq", ".login").lower() != "lmhdez":
        raise RuntimeError("Authenticate gh as LMhdez first")
    if gh("api", "repos/" + REPO, "--jq", ".permissions.admin") != "true":
        raise RuntimeError("Repository administration required")
    existing = variables()
    publisher = existing.get("GASLUX_PUBLISH_APP_CLIENT_ID")
    if not publisher:
        raise RuntimeError("Existing Publisher Client ID missing; no replacement")
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if ROOT.is_symlink() or ROOT.stat().st_uid != os.getuid() or ROOT.stat().st_mode & 0o077:
        raise RuntimeError("Unsafe local state directory")
    lock = os.open(ROOT / "setup.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    for role in ("safety", "owner"):
        for path in (ROOT/(role+".json"), ROOT/(role+".pem")):
            if path.is_symlink() or (path.exists() and
                    (path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077)):
                raise RuntimeError("Unsafe local state file")
        if existing.get("GASLUX_"+role.upper()+"_APP_CLIENT_ID") and not (ROOT/(role+".json")).exists():
            raise RuntimeError("Existing App configuration without local state; refusing replacement")
    setvar("GASLUX_AUTONOMY_PAUSED", "true")
    apps = {}
    for role in ("safety", "owner"):
        app, key = register(role, args.bind, args.port)
        apps[role] = (app, key, install(app, key))
    clients = [publisher] + [v[0]["client_id"] for v in apps.values()]
    actors = [v[2] for v in apps.values()]
    if len(set(clients)) != 3 or len(set(actors)) != 2 or set(actors)&{41898282,360620437}:
        raise RuntimeError("Independent identities required")
    desired = {"GASLUX_SAFETY_REVIEWER_ID":str(apps["safety"][2]),
               "GASLUX_BACKEND_OWNER_IDS":json.dumps(dict.fromkeys(ROLES, apps["owner"][2]), separators=(",",":")),
               "GASLUX_SUPERVISED_OWNER_IDS":json.dumps(dict.fromkeys(ROLES, apps["owner"][2]), separators=(",",":"))}
    for role,(app,key,actor) in apps.items():
        desired["GASLUX_"+role.upper()+"_APP_CLIENT_ID"] = app["client_id"]
    for name,value in desired.items():
        old = existing.get(name)
        if old and old != value:
            try:
                if json.loads(old) == json.loads(value):
                    continue
            except (ValueError,TypeError):
                pass
            raise RuntimeError("Conflicting existing configuration: "+name)
    for role,(app,key,actor) in apps.items():
        env = "gaslux-independent-"+role
        endpoint = f"repos/{REPO}/environments/{env}"
        if gh("api",endpoint,missing=True) is None:
            gh("api","-X","PUT",endpoint,"--silent")
        gh("secret","set","GASLUX_"+role.upper()+"_APP_PRIVATE_KEY","-R",REPO,"--env",env,data=key.read_bytes())
    for name,value in desired.items():
        setvar(name,value)
    for role in ("SAFETY","OWNER"):
        setvar("GASLUX_INDEPENDENT_"+role+"_ENABLED","true")
    if variables().get("GASLUX_AUTONOMY_PAUSED") != "true":
        raise RuntimeError("Pause no longer confirmed")
    print("Configuracao concluida. Autonomia PAUSADA. Chaves privadas guardadas no Pi.",flush=True)
    print("Sondagens reais apenas depois da integracao e aprovacao Safety da PR #430.",flush=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrompido; a pausa nao foi retirada.",file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print("ERRO:",str(e) if isinstance(e,RuntimeError) else type(e).__name__,file=sys.stderr)
        sys.exit(1)
