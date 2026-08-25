# AES-Rust-Lab 

![CI](https://github.com/alpha-diallo-crypto/aes-rust-lab/actions/workflows/ci.yml/badge.svg)

Implémentation pédagogique de l'algorithme **AES-128** en Rust, construite from scratch à partir des spécifications mathématiques du standard **FIPS 197**.

> **Avertissement** : ce projet est réalisé à des fins d'apprentissage. Il n'est pas destiné à remplacer une bibliothèque cryptographique auditée (comme `ring` ou `aes` en Rust). Ne pas utiliser en production.

---

## Objectif pédagogique

Comprendre et implémenter AES-128 en partant des fondements mathématiques, sans utiliser aucune bibliothèque cryptographique externe. Chaque brique est construite indépendamment et testée contre les vecteurs officiels du NIST.

---

## Structure du projet

```
src/
└── aes_core/
    ├── gf256.rs           # Arithmétique dans GF(2⁸)
    ├── sbox.rs            # S-Box construite algorithmiquement
    ├── constants.rs       # Table SBOX précalculée et constantes RCON
    ├── state.rs           # Représentation matricielle 4x4 de l'état AES
    ├── transformations.rs # SubBytes, ShiftRows, MixColumns, AddRoundKey
    ├── key_expansion.rs   # Dérivation des 44 mots de clé de round
    ├── cipher.rs          # Chiffrement AES-128 complet
    └── mod.rs             # Câblage des modules
```

---

## Implémentation détaillée

### Arithmétique dans GF(2⁸)

Corps fini défini par le polynôme irréductible AES :

```
x⁸ + x⁴ + x³ + x + 1  (0x11b)
```

| Fonction | Description |
|----------|-------------|
| `add(a, b)` | Addition = XOR |
| `xtime(a)` | Multiplication par x avec réduction modulaire |
| `mul(a, b)` | Multiplication par l'algorithme russe |
| `pow(a, n)` | Exponentiation rapide dans GF(2⁸) |
| `inv(a)` | Inverse via petit théorème de Fermat : `a⁻¹ = a²⁵⁴` |

### S-Box construite algorithmiquement

La S-Box n'est pas copiée depuis une table fixe — elle est construite à partir de l'inverse dans GF(2⁸) suivi de la transformation affine définie dans FIPS 197. Validée contre les 256 valeurs officielles.

### State : représentation matricielle 4x4

Le bloc de 16 octets est organisé en matrice colonne-major, conforme à la spécification AES.

### Transformations AES

- **SubBytes** : substitution non-linéaire via la S-Box
- **ShiftRows** : décalage cyclique des lignes
- **MixColumns** : multiplication matricielle dans GF(2⁸)
- **AddRoundKey** : XOR avec la sous-clé de round

### KeyExpansion

Dérivation des 44 mots de clé à partir d'une clé de 128 bits, via **RotWord**, **SubWord** et les constantes **RCON**.

### Chiffrement AES-128

10 rounds complets : 1 round initial + 9 rounds standards + 1 round final, validé avec le vecteur de référence officiel NIST FIPS-197.

---

## Validation NIST FIPS-197

```
plaintext  = 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
key        = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
ciphertext = 69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a 

---

## Tests

```bash
cargo test
```

**19 tests automatisés** couvrent :
- Vecteurs de multiplication AES (`mul(0x57, 0x83) = 0xc1`)
- Propriété d'ordre multiplicatif (`a²⁵⁵ = 1` pour tout `a ≠ 0`)
- Cohérence de l'inverse (`mul(a, inv(a)) = 1`)
- Vecteurs officiels KeyExpansion (W4, dernier mot)
- Vecteur de chiffrement NIST FIPS-197 complet

---

## CI/CD

GitHub Actions compile et teste automatiquement le projet à chaque push sur `main`.

---

## Technologies

- **Langage :** Rust
- **Standard :** AES (FIPS 197)
- **Domaine :** Cryptographie symétrique, Corps finis GF(2⁸)

---

## Auteur

**Alpha Amadou Diallo** — [@alpha-diallo-crypto](https://github.com/alpha-diallo-crypto)
