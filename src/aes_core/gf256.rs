/// Additionne deux éléments de GF(2^8).
///
/// Dans un corps de caractéristique 2, l'addition correspond au XOR.
pub fn add(left: u8, right: u8) -> u8 {
    left ^ right
}

/// Multiplie un octet par x, c'est-à-dire par 0x02,
/// dans le corps fini GF(2^8) utilisé par AES.
///
/// La réduction est effectuée modulo le polynôme AES :
/// x^8 + x^4 + x^3 + x + 1, représenté par 0x11b.
pub fn xtime(value: u8) -> u8 {
    if value & 0x80 != 0 {
        add(value << 1,0x1b)
    } else {
        value << 1
    }
}

/// Multiplie deux éléments de GF(2^8).
///
/// L'algorithme parcourt les 8 bits du second opérande.
/// À chaque étape, le premier opérande est multiplié par x
/// grâce à `xtime`.
pub fn mul(left: u8, right: u8) -> u8 {
    let mut multiplicand = left;
    let mut multiplier = right;
    let mut result = 0u8;
    for _ in 0..8 {
        if multiplier & 1 != 0 {
            result = add(result, multiplicand);
        }
        multiplicand = xtime(multiplicand);
        multiplier >>= 1;
    }
    result
}

/// Calcule a^n dans GF(2^8).
///
/// Pour a ≠ 0, l'exposant est réduit modulo 255 car
/// le groupe multiplicatif de GF(2^8) est d'ordre 255.
///
/// L'algorithme utilisé est le square-and-multiply
/// de gauche à droite.
pub fn pow(a: u8, n: u32) -> u8 {
    if n == 0 {
        return 1;
    }

    if a == 0 {
        return 0;
    }
    let mut result = 1;
    let mut n = (n % 255) as u8;
    for _ in 0..8 {
        if n & 0x80 != 0 {
            result = mul(mul(result, result), a)
        } else {
            result = mul(result, result)
        }
        n = n << 1;
    }
    result
}

/// Calcule l'inverse multiplicatif d'un élément de GF(2^8).
///
/// Pour `value != 0`, on utilise :
/// value^(-1) = value^254.
///
/// Par convention pour la construction de la S-box AES,
/// `inv(0)` retourne 0.
pub fn inv(value: u8) -> u8 {
    if value == 0 {
        0
    } else {
        pow(value, 254)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vérifie xtime sur un cas sans débordement et un cas avec réduction.
    #[test]
    fn test_xtime() {
        assert_eq!(xtime(0x57), 0xae);
        assert_eq!(xtime(0xae), 0x47);
    }

    /// Vérifie que l'addition GF(2^8) correspond bien à un XOR.
    #[test]
    fn test_xor() {
        assert_eq!(add(0x53, 0xca), 0x99);
    }

    /// Vérifie mul avec un petit exemple à la main et le couple (0x57, 0x83).
    #[test]
    fn test_mul() {
        assert_eq!(mul(3, 5), 15);
        assert_eq!(mul(0x57, 0x83), 0xc1);
    }

    /// Vérifie pow : cas de base, cas limite a=0, cohérence interne avec mul,
    /// vecteurs numériques précis, et la propriété de périodicité (a^255 = 1).
    #[test]
    fn test_pow() {
        // Cas de base : n'importe quoi puissance 0 = 1 (élément neutre)
        assert_eq!(pow(2, 0), 1);
        assert_eq!(pow(0x53, 0), 1);
        assert_eq!(pow(0xff, 0), 1);
        assert_eq!(pow(0, 0), 1);

        // Cas particulier a = 0 : toujours 0 pour un exposant strictement positif
        assert_eq!(pow(0, 1), 0);
        assert_eq!(pow(0, 254), 0);
        assert_eq!(pow(0, 255), 0);
        assert_eq!(pow(0, 510), 0);

        // Puissance 1 = la valeur elle-même
        assert_eq!(pow(2, 1), 2);
        assert_eq!(pow(0x53, 1), 0x53);

        // Cohérence : a^2 doit toujours égaler mul(a, a)
        assert_eq!(pow(3, 2), mul(3, 3));
        assert_eq!(pow(0x53, 2), mul(0x53, 0x53));

        // Cohérence : a^3 doit égaler mul(mul(a,a), a)
        assert_eq!(pow(3, 3), mul(mul(3, 3), 3));

        // Vecteurs numériques précis
        assert_eq!(pow(0x53, 13), 43);
        assert_eq!(pow(0xca, 100), 0xab);

        // Périodicité : a^255 = 1, donc a^(255+k) = a^k pour tout a non nul
        assert_eq!(pow(0x53, 255), 1);
        assert_eq!(pow(0x53, 256), 0x53);
        assert_eq!(pow(0x53, 257), mul(0x53, 0x53));
        assert_eq!(pow(0x53, 510), 1);
    }

    /// Vérifie inv avec le couple classique 0x53/0xca, et la propriété
    /// fondamentale a * inv(a) = 1.
    #[test]
    fn test_inv() {
        assert_eq!(inv(0x53), 0xca);
        assert_eq!(mul(0x53, inv(0x53)), 1);
    }
}