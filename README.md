# Nowości wydawnicze w Polsce

Wyszukiwarka nowo wydanych książek w Polsce, odświeżana codziennie rano. Obejmuje nowości z ostatnich 10 dni; domyślnie pokazuje ostatni dzień.

Strona: https://lexiconaw.github.io/nowosci/ (dostęp na hasło).

Strona jest zaszyfrowana hasłem (AES-256-GCM, klucz z PBKDF2-SHA256), więc w repozytorium nie ma jej czytelnej treści.

Narzędzia (hasło podaje się w zmiennej `SITE_PASSWORD`, nigdy w plikach):
- szyfrowanie: `SITE_PASSWORD=... node tools/encrypt.js zrodlo.html index.html`
- odszyfrowanie: `SITE_PASSWORD=... node tools/decrypt.js index.html zrodlo.html`
