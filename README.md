# BB-Care-Security

Professzionális WordPress védelmi plugin egyedi login URL-lel, brute force védelemmel és valós idejű email értesítésekkel.

## Funkciók

- ✅ **Egyedi Login URL** - wp-login.php elrejtés, saját bejelentkezési útvonal
- ✅ **wp-admin védelem** - vendég felhasználók 404-et kapnak
- ✅ **Brute Force védelem** - rate limiting sikertelen próbálkozásokra
- ✅ **Email értesítések** - sikeres login és blokkolt kísérletek
- ✅ **Biztonsági fejlécek** - HSTS, X-Frame-Options, X-Content-Type-Options
- ✅ **REST API védelem** - user enumeration blokkolás
- ✅ **Author enumeration védelem** - /author/ és ?author= tiltása
- ✅ **XML-RPC letiltás** - támadási felület csökkentése
- ✅ **Verzió elrejtés** - WP verzió információ eltávolítása
- ✅ **Fájlfeltöltés védelem** - veszélyes kiterjesztések tiltása
- ✅ **Érzékeny fájlok blokkolása** - readme.html, license.txt, wp-config-sample.php

## Telepítés

1. Töltsd le vagy klónozd a repót
2. Másold a `BB-Care-Security` mappát a `/wp-content/plugins/` könyvtárba
3. Aktiváld a plugint a WordPress admin felületen

## Használat

### Beállítások

WordPress Admin → **Beállítások** → **BB Security**

Itt tudod beállítani az egyedi login URL-t és a védelmi kapcsolókat.

### Egyedi login URL

Adj meg egy slugot (pl. `bb-login`) és mentsd el.
Mentés követően az új bejelentkezési URL-t emailben is elküldjük.

### Email értesítések

Kapcsold be az **Email értesítések** opciót, és állíts be egy értesítési email címet.
Értesítések a következő eseményekről mennek:

- Sikeres bejelentkezés
- Blokkolt bejelentkezési próbálkozások
- Login URL változás

## Követelmények

- WordPress 5.8+
- PHP 7.4+

## Szerzői jog

© 2026 Business Bloom Consulting®

## Support

Kérdés vagy probléma esetén nyiss egy Issue-t a GitHub-on.

---

## Security headers beállítása .htaccess-ben

Egyes tárhelyszolgáltatók nem engedik a security headerek beállítását PHP-ból.
Ilyen esetben az alábbi konfiguráció elhelyezhető a weboldal gyökérkönyvtárában található `.htaccess` fájlban.

> Feltétel: Apache webszerver és aktív `mod_headers` modul.

```apache

<IfModule mod_headers.c>

  # HSTS – CSAK HA HTTPS VAN MINDENHOL
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

  # XSS / MIME sniffing / iframe védelem
  Header set X-Content-Type-Options "nosniff"
  Header set X-Frame-Options "SAMEORIGIN"

  # Referer policy
  Header set Referrer-Policy "strict-origin-when-cross-origin"

  # Permissions policy (régi Feature-Policy utódja)
  Header set Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()"

  # Content Security Policy – ALAP, WORDPRESS-BARÁT
  Header set Content-Security-Policy "default-src 'self'; \
    script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
    style-src 'self' 'unsafe-inline'; \
    img-src 'self' data: https:; \
    font-src 'self' data: https:; \
    connect-src 'self' https:; \
    frame-ancestors 'self';"

</IfModule>
```
