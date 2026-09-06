import os, sys, subprocess, pathlib
env = {}
for line in (pathlib.Path.home()/".claude/private/swis-prod-rw.env").read_text().splitlines():
    line=line.strip()
    if line and not line.startswith("#") and "=" in line:
        k,_,v=line.partition("="); env[k.strip().replace("export ","")]=v.strip().strip('"').strip("'")
def pick(suffixes):
    for k,v in env.items():
        if any(k.upper().endswith(s) for s in suffixes): return v
    return None
os.environ["ORION_HOST"]=pick(("HOST",)) or ""; os.environ["ORION_USER"]=pick(("USER","USERNAME")) or ""; os.environ["ORION_PASSWORD"]=pick(("PASSWORD","PASS")) or ""
print("host/user set:", bool(os.environ["ORION_HOST"]), bool(os.environ["ORION_USER"]), "pw len", len(os.environ["ORION_PASSWORD"]), file=sys.stderr)
sys.exit(subprocess.call([sys.executable, "orionRTEVpull.py"] + sys.argv[1:]))
