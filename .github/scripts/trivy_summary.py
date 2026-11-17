"""Résumé Markdown des scans Trivy (image + configuration) pour le résumé du job GitHub Actions."""
import json
import sys
from collections import Counter

version, dockerfile, size, user, image_json, config_json = sys.argv[1:7]
SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

img = json.load(open(image_json, encoding="utf-8"))
cfg = json.load(open(config_json, encoding="utf-8"))

print(f"## Image tp3-app:{version} ({dockerfile})\n")
print(f"Taille : **{size}** | Utilisateur : **{user or 'root (aucune instruction USER)'}**\n")

print("### Vulnérabilités par cible\n")
print("| Cible | Type | " + " | ".join(SEV) + " | Total |")
print("|---|---|" + "---|" * (len(SEV) + 1))
total = Counter()
high = []
for r in img.get("Results", []):
    vulns = r.get("Vulnerabilities") or []
    c = Counter(v["Severity"] for v in vulns)
    total.update(c)
    if vulns:
        print(f"| {r['Target']} | {r['Type']} | " + " | ".join(str(c[s]) for s in SEV) + f" | {len(vulns)} |")
    high += [v for v in vulns if v["Severity"] in ("CRITICAL", "HIGH")]
print("| **Total** | | " + " | ".join(f"**{total[s]}**" for s in SEV) + f" | **{sum(total.values())}** |\n")

secrets = sum(len(r.get("Secrets") or []) for r in img.get("Results", []))
print(f"Secrets détectés dans les couches de l'image : **{secrets}**\n")

if high:
    print(f"### Vulnérabilités HIGH / CRITICAL ({len(high)}, 15 premières)\n")
    print("| Paquet | CVE | Sévérité | Version installée | Version corrigée |")
    print("|---|---|---|---|---|")
    for v in sorted(high, key=lambda v: (v["Severity"] != "CRITICAL", v["PkgName"]))[:15]:
        print(f"| {v['PkgName']} | {v['VulnerabilityID']} | {v['Severity']} | {v.get('InstalledVersion', '')} | {v.get('FixedVersion') or 'aucun correctif'} |")
    print()

print("### Configuration du Dockerfile (trivy config)\n")
mis = [m for r in cfg.get("Results", []) for m in (r.get("Misconfigurations") or [])]
if mis:
    print("| ID | Sévérité | Problème |")
    print("|---|---|---|")
    for m in mis:
        print(f"| {m.get('ID')} | {m.get('Severity')} | {m.get('Title')} |")
else:
    print("Aucune mauvaise configuration détectée.")
print()

ok = not high
print(f"### Security gate : {'✅ aucune vulnérabilité HIGH ou CRITICAL' if ok else '❌ ' + str(len(high)) + ' vulnérabilité(s) HIGH ou CRITICAL, image refusée'}")
